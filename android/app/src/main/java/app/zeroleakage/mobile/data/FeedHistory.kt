package app.zeroleakage.mobile.data

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Calendar
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

/**
 * On-device DNS history for the feed's Today / Yesterday / 7 days views.
 * Stays on this phone only (private database, excluded from backups), keeps 7 days, and is written in
 * batches every few seconds rather than once per lookup to save battery.
 */
object FeedHistory {
    private const val RETENTION_DAYS = 7
    private const val FLUSH_MS = 5_000L

    enum class Range(val title: String) { LIVE("Live"), TODAY("Today"), YESTERDAY("Yesterday"), WEEK("7 days") }

    data class Summary(val total: Long, val blocked: Long)

    private lateinit var db: Helper
    private val pending = ConcurrentLinkedQueue<FeedEvent>()
    private val flushing = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private class Helper(context: Context) : SQLiteOpenHelper(context, "feed_history.db", null, 1) {
        override fun onCreate(d: SQLiteDatabase) {
            d.execSQL("""CREATE TABLE feed (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, verdict TEXT NOT NULL,
                app TEXT NOT NULL, pkg TEXT, domain TEXT NOT NULL, category TEXT NOT NULL)""")
            d.execSQL("CREATE INDEX feed_ts ON feed(ts)")
        }
        override fun onUpgrade(d: SQLiteDatabase, old: Int, new: Int) = Unit
    }

    fun init(context: Context) {
        db = Helper(context.applicationContext)
        scope.launch { prune() }
    }

    /** Queues a lookup; written with the next batch. */
    fun add(e: FeedEvent) {
        if (!::db.isInitialized) return
        pending.add(e)
        if (flushing.compareAndSet(false, true)) {
            scope.launch {
                delay(FLUSH_MS)
                flushing.set(false)
                flush()
            }
        }
    }

    fun flush() {
        if (!::db.isInitialized || pending.isEmpty()) return
        runCatching {
            val w = db.writableDatabase
            w.beginTransaction()
            try {
                while (true) {
                    val e = pending.poll() ?: break
                    w.insert("feed", null, ContentValues().apply {
                        put("ts", e.time); put("verdict", e.verdict.name); put("app", e.appLabel)
                        put("pkg", e.packageName); put("domain", e.domain); put("category", e.category)
                    })
                }
                w.setTransactionSuccessful()
            } finally {
                w.endTransaction()
            }
        }
    }

    /** [from, to) in epoch ms for a range ("Live" isn't stored here). */
    fun bounds(range: Range, now: Long = System.currentTimeMillis()): Pair<Long, Long> {
        val startOfToday = Calendar.getInstance().apply {
            timeInMillis = now; set(Calendar.HOUR_OF_DAY, 0); set(Calendar.MINUTE, 0); set(Calendar.SECOND, 0); set(Calendar.MILLISECOND, 0)
        }.timeInMillis
        val day = 24 * 3_600_000L
        return when (range) {
            Range.TODAY, Range.LIVE -> startOfToday to Long.MAX_VALUE
            Range.YESTERDAY -> (startOfToday - day) to startOfToday
            Range.WEEK -> (startOfToday - 6 * day) to Long.MAX_VALUE
        }
    }

    /** Newest first. [blocked]: null = all, true = blocked/asked, false = allowed. */
    suspend fun query(range: Range, blocked: Boolean?, search: String, limit: Int = 500): List<FeedEvent> = withContext(Dispatchers.IO) {
        if (!::db.isInitialized) return@withContext emptyList()
        flush()
        val (from, to) = bounds(range)
        val where = StringBuilder("ts >= ? AND ts < ?")
        val args = mutableListOf(from.toString(), to.toString())
        when (blocked) {
            true -> where.append(" AND verdict <> 'ALLOWED'")
            false -> where.append(" AND verdict = 'ALLOWED'")
            null -> Unit
        }
        if (search.isNotBlank()) {
            where.append(" AND (domain LIKE ? OR app LIKE ? OR category LIKE ?)")
            val like = "%${search.trim()}%"
            args += listOf(like, like, like)
        }
        val out = ArrayList<FeedEvent>()
        runCatching {
            db.readableDatabase.query("feed", arrayOf("id", "ts", "verdict", "app", "pkg", "domain", "category"),
                where.toString(), args.toTypedArray(), null, null, "ts DESC", limit.toString()).use { c ->
                while (c.moveToNext()) {
                    out += FeedEvent(
                        id = -c.getLong(0), time = c.getLong(1),
                        verdict = runCatching { Verdict.valueOf(c.getString(2)) }.getOrDefault(Verdict.BLOCKED),
                        appLabel = c.getString(3), packageName = c.getString(4), domain = c.getString(5), category = c.getString(6),
                    )
                }
            }
        }
        out
    }

    suspend fun summary(range: Range): Summary = withContext(Dispatchers.IO) {
        if (!::db.isInitialized) return@withContext Summary(0, 0)
        flush()
        val (from, to) = bounds(range)
        runCatching {
            db.readableDatabase.rawQuery(
                "SELECT COUNT(*), COALESCE(SUM(CASE WHEN verdict <> 'ALLOWED' THEN 1 ELSE 0 END),0) FROM feed WHERE ts >= ? AND ts < ?",
                arrayOf(from.toString(), to.toString()),
            ).use { c -> if (c.moveToFirst()) Summary(c.getLong(0), c.getLong(1)) else Summary(0, 0) }
        }.getOrDefault(Summary(0, 0))
    }

    private fun prune() {
        runCatching {
            val cutoff = System.currentTimeMillis() - RETENTION_DAYS * 24 * 3_600_000L
            db.writableDatabase.delete("feed", "ts < ?", arrayOf(cutoff.toString()))
        }
    }

    fun clear() {
        pending.clear()
        if (::db.isInitialized) scope.launch { runCatching { db.writableDatabase.delete("feed", null, null) } }
    }
}
