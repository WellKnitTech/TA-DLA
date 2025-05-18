import importlib.metadata

def get_scraper_plugins():
    plugins = []
    for entry_point in importlib.metadata.entry_points(group='ta_dla.scrapers'):
        plugin_class = entry_point.load()
        plugins.append(plugin_class())
    return plugins 