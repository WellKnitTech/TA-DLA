from setuptools import setup, find_packages

setup(
    name='ta-dla',
    version='0.1.0',
    description='TA-DLA: Modular toolkit for DFIR ransomware leak analysis',
    author='Your Name',
    author_email='your.email@example.com',
    packages=find_packages(),
    install_requires=[
        'requests',
        'beautifulsoup4',
        # Add other dependencies as needed
    ],
    entry_points={
        'ta_dla.scrapers': [
            'safepay = ta_dla.scraper.safepay:SafepayScraper',
        ],
        'ta_dla.downloaders': [
            'http = ta_dla.downloader.http_downloader:HTTPDownloader',
        ],
    },
    include_package_data=True,
    zip_safe=False,
) 