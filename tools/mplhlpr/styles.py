#!/usr/bin/python
"""
Load Matplotlib styles specified by SHOTGUN_MPLSTYLES env var.

Multiple styles are separated by comma:
SHOTGUN_MPLSTYLES=shotgun,tableau-colorblind10,fast

Default is "shotgun", which distributed with Shotgun itself.

Load attempts are done in this order:
    1. Style name taken verbatim as file path
    2. Relative base name pointing directory with this module
    3. Matplotlib supplied style name (see matplotlib.style module)
"""
from pathlib import Path
import os

import matplotlib.style

SCRIPT_DIR = Path(__file__).parent


# style name "default" would be nicer, but it is reserved by matplotlib
def configure_mpl_styles(comma_list=os.environ.get("SHOTGUN_MPLSTYLES", "shotgun")):
    styles = comma_list.split(",")
    for style in styles:
        candidates = [Path(style), SCRIPT_DIR / f"{style}.mplstyle", style]
        for candidate in candidates:
            if isinstance(candidate, Path) and not candidate.exists():
                continue
            # raises if the style cannot be found
            matplotlib.style.use(candidate)
            break


def ax_set_title(ax, title):
    """show title only if style defines titlesize > 0"""
    titlesize = matplotlib.rcParams["axes.titlesize"]
    if not isinstance(titlesize, (int, float)) or titlesize > 0:
        ax.set_title(title)
