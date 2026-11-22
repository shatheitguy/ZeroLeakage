using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using ZeroLeakage.UI.Models;
using ZeroLeakage.UI.Mvvm;
using ZeroLeakage.UI.Services;

namespace ZeroLeakage.UI.ViewModels;

public sealed class WizardStep : ObservableObject
{
    private bool _isActive, _isDone;
    public required int Index { get; init; }
    public required string Title { get; init; }
    public string Number => (Index + 1).ToString("00");
    public bool IsActive { get => _isActive; set => SetProperty(ref _isActive, value); }
    public bool IsDone { get => _isDone; set => SetProperty(ref _isDone, value); }
}

/// <summary>Post-install system audit: Scan → Scorecard → Hardening → Done.</summary>
public sealed class AuditWizardViewModel : ObservableObject
{
    private readonly MainViewModel _shell;
    private readonly IProtectionEngine _engine;
    private readonly UiSettings _settings;
    private CancellationTokenSource? _cts;

    private bool _isOpen, _isAuditing, _isApplying;
    private int _step;
    private double _progress;
    private string _stage = "";
    private AuditReport? _report;

    public AuditWizardViewModel(MainViewModel shell, IProtectionEngine engine, UiSettings settings)
    {
        _shell = shell;
        _engine = engine;
        _settings = settings;

        string[] titles = { "System Audit", "Scorecard", "Hardening", "Zero-Leak" };
        for (int i = 0; i < titles.Length; i++) Steps.Add(new WizardStep { Index = i, Title = titles[i] });

        NextCommand = new AsyncRelayCommand(NextAsync, () => !IsAuditing && !IsApplying);
        BackCommand = new RelayCommand(() => Step--, () => Step is 1 or 2 && !IsApplying);
        SkipCommand = new RelayCommand(Close, () => !IsApplying);
        SelectAllCommand = new RelayCommand(() =>
        {
            bool all = Recommendations.All(r => r.IsSelected);
            foreach (var r in Recommendations) r.IsSelected = !all;
            OnPropertyChanged(nameof(ProjectedScore));
        });
    }

    public ObservableCollection<WizardStep> Steps { get; } = new();
    public ObservableCollection<string> AuditLog { get; } = new();
    public ObservableCollection<AuditCategory> Categories { get; } = new();
    public ObservableCollection<AuditRecommendation> Recommendations { get; } = new();

    public ICommand NextCommand { get; }
    public ICommand BackCommand { get; }
    public ICommand SkipCommand { get; }
    public ICommand SelectAllCommand { get; }

    public bool IsOpen { get => _isOpen; private set => SetProperty(ref _isOpen, value); }
    public bool IsAuditing { get => _isAuditing; private set { if (SetProperty(ref _isAuditing, value)) OnPropertyChanged(nameof(PrimaryText)); } }
    public bool IsApplying { get => _isApplying; private set { if (SetProperty(ref _isApplying, value)) OnPropertyChanged(nameof(PrimaryText)); } }
    public double Progress { get => _progress; private set { if (SetProperty(ref _progress, value)) OnPropertyChanged(nameof(ProgressText)); } }
    public string ProgressText => $"{_progress:0}%";
    public string Stage { get => _stage; private set => SetProperty(ref _stage, value); }

    public int Step
    {
        get => _step;
        private set
        {
            if (!SetProperty(ref _step, value)) return;
            foreach (var s in Steps) { s.IsActive = s.Index == value; s.IsDone = s.Index < value; }
            OnPropertyChanged(nameof(PrimaryText));
            OnPropertyChanged(nameof(ProjectedScore));
        }
    }

    public int Score => _report?.Score ?? 0;
    public string ScoreVerdict => Score switch { < 40 => "Leaking heavily", < 70 => "Partially exposed", _ => "Well protected" };

    public Brush ScoreBrush => (Brush)Application.Current.FindResource(Score switch
    {
        < 40 => "Brush.Crimson",
        < 70 => "Brush.Amber",
        _ => "Brush.Mint",
    });

    public int SelectedCount => Recommendations.Count(r => r.IsSelected);
    public int ProjectedScore => Math.Min(100, Score + Recommendations.Where(r => r.IsSelected).Sum(r => r.ScoreGain));

    public string PrimaryText => Step switch
    {
        0 => IsAuditing ? "Auditing…" : "View scorecard",
        1 => "Fix these leaks",
        2 => IsApplying ? "Applying…" : $"Apply {SelectedCount} protections",
        _ => "Enter dashboard",
    };

    public void Open()
    {
        Step = -1;
        Step = 0;
        IsOpen = true;
        _ = RunAuditAsync();
    }

    private void Close()
    {
        _cts?.Cancel();
        IsOpen = false;
        _settings.WizardCompleted = true;
        UiSettingsStore.Save(_settings);
    }

    private async Task RunAuditAsync()
    {
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        AuditLog.Clear();
        Categories.Clear();
        Recommendations.Clear();
        Progress = 0;
        IsAuditing = true;
        try
        {
            _report = await _engine.RunAuditAsync(new Progress<AuditProgress>(p =>
            {
                Progress = p.Percent;
                if (p.Stage != Stage)
                {
                    Stage = p.Stage;
                    AuditLog.Add(p.Stage);
                }
            }), _cts.Token);

            foreach (var c in _report.Categories) Categories.Add(c);
            foreach (var r in _report.Recommendations)
            {
                r.PropertyChanged += (_, _) => { OnPropertyChanged(nameof(ProjectedScore)); OnPropertyChanged(nameof(SelectedCount)); OnPropertyChanged(nameof(PrimaryText)); };
                Recommendations.Add(r);
            }
            Stage = "Audit complete";
            OnPropertyChanged(nameof(Score));
            OnPropertyChanged(nameof(ScoreVerdict));
            OnPropertyChanged(nameof(ScoreBrush));
            OnPropertyChanged(nameof(ProjectedScore));
            OnPropertyChanged(nameof(SelectedCount));
        }
        catch (OperationCanceledException) { }
        finally { IsAuditing = false; }
    }

    private async Task NextAsync()
    {
        switch (Step)
        {
            case 0:
            case 1:
                Step++;
                break;
            case 2:
                IsApplying = true;
                try
                {
                    var snapshot = await _engine.CreateSnapshotAsync($"Before hardening wizard · {DateTime.Now:dd MMM HH:mm}");
                    _shell.Settings.Snapshots.Insert(0, snapshot);
                    await _engine.ApplyRecommendationsAsync(Recommendations.Where(r => r.IsSelected).ToList());
                    if (Recommendations.Any(r => r.IsSelected && r.Id == "firewall") && _shell.Mode == ProtectionMode.Balanced)
                        _shell.Mode = ProtectionMode.StrictGuard;
                }
                finally { IsApplying = false; }
                Step = 3;
                break;
            default:
                Close();
                _shell.ShowSnackbar($"Hardening applied · privacy score {ProjectedScore}/100");
                break;
        }
    }
}
