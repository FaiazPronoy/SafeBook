# The server's own key material has no per-user rows any more: a user's
# private DEK is held by their password, and the only thing the server KEK
# wraps is the content key of each public post, which lives on the post.
#
# The app is kept for what it still owns - reading and validating the KEK,
# and the rotation command that re-wraps every public post key when the KEK
# changes.
