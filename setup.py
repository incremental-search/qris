from setuptools import setup

setup(
    name='qris',
    version='1.0',
    description='Query Recognition in Incremental Search',
    url='http://github.com/incremental-search/qris',
    license='GPL',
    packages=['qris'],
    package_dir={'qris': 'qris'},
    package_data={'qris': ['models/*']},
    include_package_data=True,
    entry_points={
        'console_scripts': ['qris = qris.__main__:main']
    },
    install_requires=[
		'numpy>=1.15.1',
        'pandas>=0.23.4',
		'xpinyin>=0.5.7',
        'dpkt>=1.9.2',
		'hpack>=3.0.0',
        'scipy>=1.1.0',
		'tqdm>=4.29.1'
    ],
    zip_safe=False
)
