# Google Maps API Scanner Web Based
Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.  

Please Note:- This is Not Devloped by me. I have justed Modifed Few code, All the Logic and Hardwork was done by https://github.com/ozguralp 


***Usage:***
- Visit https://gmapsapiscannerweb.onrender.com/
- As Of now No POC, Will be added Later 

***Checked APIs:***
- Staticmap API
- Streetview API
- <s>Embed (Basic-Free) API</s> (No longer checked since it is completely free.)
- <s>Embed (Advanced-Paid) API</s> (No longer checked since it is completely free.)
- Directions API
- Geocode API
- Distance Matrix API
- Find Place From Text API
- Autocomplete API
- Elevation API
- Timezone API
- Roads API
- Geolocation API
- Route to Traveled API
- Speed Limit-Roads API
- Place Details API
- Nearby Search-Places API
- Text Search-Places API
- Places Photo API
- <s>Playable Locations API</s> (API is deprecated.)
- FCM API
- Custom Search API

***Semi-Auto Checked APIs:***
- JavaScript API

***Notes:***
- Because JavaScript API needs manual confirmation from a web browser directly, only file is created via the script for manual checks/confirmation.
- For Staticmap, Streetview and Embed API's, if used from another domain instead of just testing from browser; whether referer checks are enabled or not on the server-side for the key, script still could return it as vulnerable due to a server-side vulnerability. If you cannot reproduce the vulnerability via browser while the script says so, please read the ***Blog Post #2*** for more information & a better understanding about what is going on. 
- If you find any Google Maps API's which are not mentioned in this document/script, create an issue with details so I can also add them.
- Special thanks to [Yatin](https://twitter.com/ysirpaul) for his contributions on both discovery of additional API's & cost information!



