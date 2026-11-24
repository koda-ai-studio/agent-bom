### Changed
- The compact graph canvas draws relationships as solid 2.2 px lines (3.2 px on a selected path) instead of thin 1.4 px lines, and entity glyphs about 15% larger. The Internet boundary is drawn as a larger anchor for the exposure story it starts.
- When every link in a view is modeled, the lines are drawn solid and the legend says "Every link in this view is modeled, not recorded"; a dash only appears where it distinguishes modeled or blocked links from recorded ones.
- The Internet arrow takes its own entry on the upper left of a node that another link also enters, so the two arrowheads no longer land on one point, and the node's separate exposure dot is not drawn when the anchor already shows it.

### Fixed
- Link routing, the room under two-line names and resting edge labels follow the drawn glyph size from one shared constant, so larger glyphs never push captions into the card below or labels onto a glyph.
