package app.zeroleakage.mobile.ui.screens

import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.zeroleakage.mobile.data.ServerLink
import app.zeroleakage.mobile.data.ZeroLeakage
import app.zeroleakage.mobile.filters.Filters
import app.zeroleakage.mobile.ui.components.Chip
import app.zeroleakage.mobile.ui.components.GlassCard
import app.zeroleakage.mobile.ui.components.Overline
import app.zeroleakage.mobile.ui.theme.Zl
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Account & sync: link this phone to your ZeroLeakage Server (pairing code or sign-in), see sync status, unlink. */
@Composable
fun ServerLinkScreen(onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    val link by ServerLink.link.collectAsStateWithLifecycle()
    val sync by ServerLink.sync.collectAsStateWithLifecycle()

    var server by rememberSaveable { mutableStateOf("") }
    var usePassword by rememberSaveable { mutableStateOf(false) }
    var code by rememberSaveable { mutableStateOf("") }
    var username by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var deviceName by rememberSaveable { mutableStateOf("${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL}") }
    var busy by rememberSaveable { mutableStateOf(false) }
    var error by rememberSaveable { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize().background(Zl.Canvas).statusBarsPadding().navigationBarsPadding().imePadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(44.dp).clip(CircleShape).clickable(onClick = onClose), contentAlignment = Alignment.Center) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Zl.TextPrimary)
            }
            Text("Account & sync", fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
        }
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 14.dp, vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            val l = link
            if (l == null) {
                GlassCard(accent = Zl.Violet) {
                    Overline("Connect to your ZeroLeakage Server", color = Zl.TextPrimary)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Optional. Once linked, this phone copies your server's protection exactly: filter lists, blocked services, " +
                            "categories, SafeSearch, schedules and your allow / block lists, and uses the server as its encrypted DNS. " +
                            "Changes you make here sync to your other devices. Settings from your admin can't be weakened here.",
                        fontSize = 12.sp, color = Zl.TextSecondary, lineHeight = 17.sp,
                    )
                    Spacer(Modifier.height(12.dp))
                    Field(server, { server = it; error = null }, "Server address", "https://dns.example.com", KeyboardType.Uri)
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        Chip("Pairing code", !usePassword, Zl.Violet, { usePassword = false })
                        Chip("Sign in", usePassword, Zl.Violet, { usePassword = true })
                    }
                    Spacer(Modifier.height(8.dp))
                    if (usePassword) {
                        Field(username, { username = it; error = null }, "Username", "", KeyboardType.Text)
                        Spacer(Modifier.height(8.dp))
                        Field(password, { password = it; error = null }, "Password", "", KeyboardType.Password, secret = true)
                    } else {
                        Field(code, { code = it.uppercase(); error = null }, "Pairing code", "ZL-XXXX-XXXX", KeyboardType.Ascii)
                        Text("Get one in your server's dashboard: Devices → Add device → Pairing code.", fontSize = 11.sp, color = Zl.TextMuted)
                    }
                    Spacer(Modifier.height(8.dp))
                    Field(deviceName, { deviceName = it }, "This phone's name", "", KeyboardType.Text)
                    error?.let { Spacer(Modifier.height(6.dp)); Text(it, fontSize = 12.sp, color = Zl.Crimson) }
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = {
                            busy = true; error = null
                            scope.launch {
                                error = if (usePassword) ServerLink.signIn(server, username, password, deviceName)
                                else ServerLink.pair(server, code, deviceName)
                                password = ""
                                busy = false
                                if (error == null) ZeroLeakage.say("Linked. This phone now follows your server.")
                            }
                        },
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth().height(48.dp), shape = RoundedCornerShape(12.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Zl.Violet, contentColor = Zl.Canvas),
                    ) { Text(if (busy) "Linking…" else "Link this phone", fontWeight = FontWeight.Bold) }
                    Spacer(Modifier.height(6.dp))
                    Text("Your server must use https: your rules and DNS never travel unencrypted.", fontSize = 11.sp, color = Zl.TextMuted)
                }
            } else {
                GlassCard(accent = Zl.Mint) {
                    Overline("Linked", color = Zl.TextPrimary)
                    Spacer(Modifier.height(6.dp))
                    Text(l.serverName, fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = Zl.TextPrimary)
                    Text(l.server, style = Zl.mono.copy(fontSize = 11.sp, color = Zl.TextMuted))
                    Spacer(Modifier.height(8.dp))
                    Detail("Signed in as", l.username ?: "(paired device)")
                    Detail("This device", l.deviceName)
                    Detail("Encrypted DNS", l.dohUrl ?: "—")
                    Detail("Linked since", fmt(l.linkedAt))
                    Spacer(Modifier.height(10.dp))
                    when (val s = sync) {
                        ServerLink.Sync.Running -> Text("Syncing…", fontSize = 12.5.sp, color = Zl.Violet)
                        is ServerLink.Sync.Ok -> Text(
                            "✓ In sync · ${fmt(s.at)} · ${s.lists} lists · ${s.block} blocked · ${s.allow} allowed" +
                                (if (s.services > 0) " · ${s.services} services blocked" else ""),
                            fontSize = 12.5.sp, color = Zl.Mint,
                        )
                        is ServerLink.Sync.Failed -> Text("⚠ ${s.message} (${fmt(s.at)})", fontSize = 12.5.sp, color = Zl.Amber)
                        ServerLink.Sync.Idle -> Unit
                    }
                    if (Filters.lockedLists.isNotEmpty() || Filters.lockedBlock.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text("Your admin enforces ${Filters.lockedLists.size} lists and ${Filters.lockedBlock.size} blocked domains on this device.",
                            fontSize = 11.5.sp, color = Zl.TextSecondary)
                    }
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        SmallAction("Sync now", Zl.Mint) { scope.launch { ServerLink.syncNow() } }
                        SmallAction("Unlink", Zl.Crimson) {
                            ServerLink.unlink()
                            ZeroLeakage.say("Unlinked. Your previous DNS settings are back.")
                        }
                    }
                }
            }
        }
    }
}

private fun fmt(t: Long) = SimpleDateFormat("dd MMM HH:mm", Locale.US).format(Date(t))

@Composable
private fun Detail(k: String, v: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
        Text(k, fontSize = 12.sp, color = Zl.TextMuted, modifier = Modifier.weight(0.4f))
        Text(v, style = Zl.mono.copy(fontSize = 11.5.sp, color = Zl.TextPrimary), modifier = Modifier.weight(0.6f))
    }
}

@Composable
private fun Field(value: String, onChange: (String) -> Unit, label: String, hint: String, type: KeyboardType, secret: Boolean = false) {
    OutlinedTextField(
        value = value, onValueChange = onChange, singleLine = true,
        label = { Text(label) }, placeholder = { if (hint.isNotEmpty()) Text(hint, color = Zl.TextMuted) },
        keyboardOptions = KeyboardOptions(keyboardType = type, autoCorrectEnabled = false),
        visualTransformation = if (secret) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        modifier = Modifier.fillMaxWidth(),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Zl.Violet, unfocusedBorderColor = Zl.Border,
            focusedTextColor = Zl.TextPrimary, unfocusedTextColor = Zl.TextPrimary, cursorColor = Zl.Violet,
            focusedLabelColor = Zl.Violet, unfocusedLabelColor = Zl.TextMuted,
        ),
    )
}
