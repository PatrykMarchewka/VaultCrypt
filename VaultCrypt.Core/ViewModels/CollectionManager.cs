using System.Collections;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace VaultCrypt.ViewModels;

/// <summary>
/// Manages a collection by exposing filtering and sorting options
/// </summary>
/// <param name="source">Collection to manage</param>
/// <typeparam name="T">Type of the items in collection</typeparam>
public sealed class CollectionManager<T>(IEnumerable<T> source) : INotifyPropertyChanged, IEnumerable<T>
{
    public Func<T, bool>?  Filter { get; set; }
    public Comparison<T>? Sort { get; set; }

    public IEnumerable<T> Items => ApplySort(ApplyFilter(source));

    public void Refresh()
    {
        OnPropertyChanged(nameof(Items));
    }

    private IEnumerable<T> ApplySort(IEnumerable<T> items) =>
        Sort is null ? items : items.OrderBy(item => item, Comparer<T>.Create(Sort));
    private IEnumerable<T> ApplyFilter(IEnumerable<T> items) => Filter is null ? items : items.Where(Filter);

    public bool IsEmpty => source.Any();

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public IEnumerator<T> GetEnumerator() => source.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}