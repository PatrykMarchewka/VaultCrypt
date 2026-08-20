using VaultCrypt.ViewModels;

namespace VaultCrypt.Tests.ViewModels;

public class CollectionManagerTests
{
    private readonly List<int> _testData = new List<int>() { 1, 2, 3, 4, 5 };

    [Fact]
    internal void ItemsReturnsCorrectForUnsortedUnfiltered()
    {
        var manager = new CollectionManager<int>(_testData);
        
        Assert.Equal(_testData, manager.Items);
    }

    [Fact]
    internal void ItemsReturnsCorrectForSortedUnfiltered()
    {
        var expected = _testData;
        var manager = new CollectionManager<int>(_testData);

        //Reverses the order
        manager.Sort = (first, second) => second.CompareTo(first);

        expected.Reverse();
        Assert.Equal(expected, manager.Items);
    }

    [Fact]
    internal void ItemsReturnsCorrectForSortedAndFiltered()
    {
        var expected = _testData;
        var manager = new CollectionManager<int>(_testData);
        
        //Reverses the order
        manager.Sort = (first, second) => second.CompareTo(first);
        manager.Filter = item => item % 2 == 0;

        expected.Reverse();
        
        Assert.Equal(expected.Where(item => item % 2 == 0), manager.Items);
    }

    [Fact]
    internal void RefreshRaisesPropertyChanged()
    {
        var manager = new CollectionManager<int>(_testData);
        int propertyRaisedCount = 0;
        manager.PropertyChanged += (sender, args) => propertyRaisedCount++;
        
        manager.Refresh();
        
        Assert.Equal(1, propertyRaisedCount);
    }

    [Fact]
    internal void RefreshRaisesPropertyChangedOnEachCall()
    {
        var manager = new CollectionManager<int>(_testData);
        int propertyRaisedCount = 0;
        manager.PropertyChanged += (sender, args) => propertyRaisedCount++;
        
        manager.Refresh();
        manager.Refresh();
        manager.Refresh();
        manager.Refresh();
        manager.Refresh();
        
        Assert.Equal(5, propertyRaisedCount);
    }
}