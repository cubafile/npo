You can find the token in the response header from the network request player-token (POST). 
The token requires two prerequisites to get automatically:

CSRF: Can be grabbed with another network request, session(GET), where it's set as a browser cookie.
productId: This is what determines what video you want to download. Sent to the browser as part of a huge json blob on the first request, alongside a bunch of other productIds for the other videos visible.
Since the video URL includes a slug, I used that to search.
