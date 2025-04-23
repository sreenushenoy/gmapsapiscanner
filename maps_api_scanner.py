import requests
import warnings
import os

def scan_gmaps(apikey):
    results = []
    vulnerable_apis = []

    def check(name, url, method="GET", data=None, headers=None, expect=None, error_field="error_message", check_status=None):
        try:
            if method == "POST":
                res = requests.post(url, data=data, headers=headers, verify=False)
            else:
                res = requests.get(url, headers=headers, verify=False, allow_redirects=False)

            txt = res.text

            if check_status == "302":
                vulnerable = res.status_code == 302
            elif expect:
                vulnerable = expect in txt
            else:
                vulnerable = error_field not in txt

            if vulnerable:
                results.append(f"🔴 {name} is VULNERABLE!\n→ {url}\n")
                vulnerable_apis.append(name)
            else:
                try:
                    reason = res.json().get(error_field, "No error message.")
                except:
                    if "image" in res.headers.get("Content-Type", ""):
                        reason = "Binary image content returned (likely a valid response, not an error)."
                    else:
                        reason = res.content.decode(errors='ignore')
                results.append(f"🟢 {name} is NOT vulnerable.\nReason: {reason}\n")
        except Exception as e:
            results.append(f"⚠️ Error testing {name}: {str(e)}")

    # 🌐 Core vulnerability checks
    check("Staticmap", f"https://maps.googleapis.com/maps/api/staticmap?center=45,10&zoom=7&size=400x400&key={apikey}", expect="PNG")
    check("Streetview", f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&key={apikey}", expect="PNG")
    check("Directions", f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={apikey}")
    check("Geocode", f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={apikey}")
    check("Distance Matrix", f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615,-73.9976592&key={apikey}")
    check("Find Place From Text", f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key={apikey}")
    check("Autocomplete", f"https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=(cities)&key={apikey}")
    check("Elevation", f"https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={apikey}")
    check("Timezone", f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={apikey}", error_field="errorMessage")
    check("Nearest Roads", f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key={apikey}", error_field="message")
    check("Geolocation", f"https://www.googleapis.com/geolocation/v1/geolocate?key={apikey}", method="POST", data={'considerIp': 'true'}, error_field="message")
    check("Route to Traveled", f"https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key={apikey}", error_field="message")
    check("Speed Limit-Roads", f"https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key={apikey}", error_field="message")
    check("Place Details", f"https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key={apikey}")
    check("Nearby Search-Places", f"https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key={apikey}")
    check("Text Search-Places", f"https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={apikey}")
    check("Places Photo", f"https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key={apikey}", check_status="302")
    check("FCM API", f"https://fcm.googleapis.com/fcm/send", method="POST", data="{'registration_ids':['ABC']}", headers={'Content-Type':'application/json','Authorization':'key='+apikey})

    # 🧾 Final summary
    results.append("\n------------------ SUMMARY ------------------")
    if vulnerable_apis:
        results.append("🔴 Vulnerable APIs:")
        for api in vulnerable_apis:
            results.append(f"- {api}")
    else:
        results.append("✅ No vulnerable APIs detected.")
    results.append("---------------------------------------------")

    return "\n".join(results)

warnings.filterwarnings("ignore")
