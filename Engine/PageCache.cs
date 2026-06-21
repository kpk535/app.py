using System;
using System.Collections.Generic;

namespace WebBrowser.Engine;

public class PageCache
{
    private readonly int _capacity;
    private readonly TimeSpan _ttl;
    private readonly Dictionary<string, CacheEntry> _cache = new();
    private readonly LinkedList<string> _lruList = new();

    public PageCache(int capacity = 50, int ttlMinutes = 10)
    {
        _capacity = capacity;
        _ttl = TimeSpan.FromMinutes(ttlMinutes);
    }

    public WebPage? Get(string url)
    {
        if (!_cache.TryGetValue(url, out var entry)) return null;
        if (DateTime.UtcNow - entry.CachedAt > _ttl)
        {
            Remove(url);
            return null;
        }
        _lruList.Remove(entry.Node);
        _lruList.AddFirst(entry.Node);
        entry.Page.IsFromCache = true;
        return entry.Page;
    }

    public void Put(string url, WebPage page)
    {
        if (_cache.ContainsKey(url))
            Remove(url);

        if (_cache.Count >= _capacity && _lruList.Last is { } last)
            Remove(last.Value);

        var node = _lruList.AddFirst(url);
        _cache[url] = new CacheEntry { Page = page, Node = node, CachedAt = DateTime.UtcNow };
    }

    public void Remove(string url)
    {
        if (_cache.TryGetValue(url, out var entry))
        {
            _lruList.Remove(entry.Node);
            _cache.Remove(url);
        }
    }

    public void Clear() { _cache.Clear(); _lruList.Clear(); }

    public int Count => _cache.Count;

    private class CacheEntry
    {
        public required WebPage Page { get; set; }
        public required LinkedListNode<string> Node { get; set; }
        public DateTime CachedAt { get; set; }
    }
}
