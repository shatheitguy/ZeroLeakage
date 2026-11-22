using System;
using System.Collections.Generic;
using System.Windows.Threading;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.ViewModels;
using ZeroLeakage.UI.Views;

namespace ZeroLeakage.UI.Services;

/// <summary>Queues "Ask to Connect" requests and shows them one toast at a time.</summary>
public sealed class ConnectToastService : IDisposable
{
    private readonly IProtectionEngine _engine;
    private readonly Dispatcher _dispatcher;
    private readonly Queue<ConnectionRequest> _queue = new();
    private ConnectToastWindow? _current;

    public ConnectToastService(IProtectionEngine engine, Dispatcher dispatcher)
    {
        _engine = engine;
        _dispatcher = dispatcher;
        _engine.ConnectionRequested += OnRequested;
    }

    private void OnRequested(object? sender, ConnectionRequest request)
        => _dispatcher.InvokeAsync(() =>
        {
            _queue.Enqueue(request);
            ShowNext();
        });

    private void ShowNext()
    {
        if (_current is not null || _queue.Count == 0) return;

        var request = _queue.Dequeue();
        var vm = new ConnectToastViewModel(request);
        vm.Decided += async (_, decision) =>
        {
            try { await _engine.SubmitDecisionAsync(request, decision); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
        };

        _current = new ConnectToastWindow(vm);
        _current.Closed += (_, _) =>
        {
            _current = null;
            ShowNext();
        };
        _current.Show();
    }

    public void Dispose()
    {
        _engine.ConnectionRequested -= OnRequested;
        _queue.Clear();
        _current?.Close();
    }
}
