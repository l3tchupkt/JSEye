"""ASCII Banner for JSEye v2.0."""

import asyncio
import aiohttp
from typing import Optional
from ..version import __version__


async def check_latest_version() -> Optional[str]:
    """Check the latest version available on PyPI."""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.get('https://pypi.org/pypi/jseye/json') as response:
                if response.status == 200:
                    data = await response.json()
                    return data['info']['version']
    except Exception:
        # Silently fail if we can't check version
        pass
    return None


def get_ascii_banner() -> str:
    """Get the JSEye ASCII banner with proper alignment."""
    banner = r"""
     ____.  ____________________
    |    | /   _____/\_   _____/___.__.  ____
    |    | \_____  \  |    __)_<   |  |_/ __ \
/\__|    | /        \ |        \\___  |\  ___/
\________|/_______  //_______  // ____| \___  >
                  \/         \/ \/          \/
"""
    
    return banner


def get_full_banner() -> str:
    """Get the complete banner with version and description."""
    ascii_art = get_ascii_banner()
    
    banner = f"""{ascii_art}
        JavaScript Intelligence & Attack Surface Discovery
                        Version {__version__}
                   Author: Lakshmikanthan K (@letchupkt)
"""
    
    return banner


async def print_banner_async() -> None:
    """Print the banner with colors, alignment, and version check."""
    try:
        from rich.console import Console
        from rich.align import Align
        from rich.text import Text
        
        console = Console()
        
        # Print ASCII art in cyan, centered
        ascii_art = get_ascii_banner()
        console.print(Align.center(ascii_art), style="cyan bold")
        
        # Print description in green, centered
        console.print(Align.center("JavaScript Intelligence & Attack Surface Discovery"), 
                     style="green bold")
        
        # Print version info, centered
        console.print(Align.center(f"Version {__version__}"), 
                     style="white")
        
        # Print author in magenta, centered
        console.print(Align.center("Author: Lakshmikanthan K (@letchupkt)"), 
                     style="magenta")
        
        # Check for updates asynchronously
        latest_version = await check_latest_version()
        if latest_version and latest_version != __version__:
            try:
                from packaging import version
                if version.parse(latest_version) > version.parse(__version__):
                    console.print(Align.center(f"[!] Update available: v{latest_version} (current: v{__version__})"), 
                                 style="yellow")
                    console.print(Align.center("Run: pip install --upgrade jseye"), 
                                 style="yellow dim")
            except ImportError:
                # Fallback without version comparison
                console.print(Align.center(f"[!] Latest version: v{latest_version} (current: v{__version__})"), 
                             style="yellow")
        elif latest_version == __version__:
            console.print(Align.center("You're running the latest version"), 
                         style="green dim")
        
        console.print()  # Empty line
        
    except ImportError:
        # Fallback if rich is not available
        print(get_full_banner())


def print_banner() -> None:
    """Print the banner with colors and proper alignment (sync version)."""
    try:
        from rich.console import Console
        from rich.align import Align
        
        console = Console()
        
        # Print ASCII art in cyan, centered
        ascii_art = get_ascii_banner()
        console.print(Align.center(ascii_art), style="cyan bold")
        
        # Print description in green, centered
        console.print(Align.center("JavaScript Intelligence & Attack Surface Discovery"), 
                     style="green bold")
        
        # Print version info, centered
        console.print(Align.center(f"Version {__version__}"), 
                     style="white")
        
        # Print author in magenta, centered
        console.print(Align.center("Author: Lakshmikanthan K (@letchupkt)"), 
                     style="magenta")
        
        console.print()  # Empty line
        
    except ImportError:
        # Fallback if rich is not available
        print(get_full_banner())