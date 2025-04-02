from app.extensions import db
import requests
import datetime
import pytz

def fetch_live_weather_for_garden(uid, garden_id):
    garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
    doc = garden_ref.get()
    if not doc.exists:
        raise ValueError("Garden not found")

    location = doc.to_dict().get("location")
    if not location or "lat" not in location or "lon" not in location:
        raise ValueError("Location must include lat/lon")

    lat = location["lat"]
    lon = location["lon"]

    url = (
        f"https://api.open-meteo.com/v1/forecast"
        f"?latitude={lat}&longitude={lon}"
        f"&current=temperature_2m,relative_humidity_2m,pressure_msl,uv_index,weathercode"
    )

    response = requests.get(url)
    response.raise_for_status()
    current = response.json().get("current", {})

    return {
        "temperature": current.get("temperature_2m"),
        "humidity": current.get("relative_humidity_2m"),
        "pressure": current.get("pressure_msl"),
        "uv_index": current.get("uv_index"),
        "weather_symbol": current.get("weathercode")
    }

def fetch_weather_history_for_garden(uid, garden_id):
    weather_ref = db.collection("users").document(uid).collection("gardens").document(garden_id).collection("weather_data")
    docs = weather_ref.stream()

    history = []
    for doc in docs:
        data = doc.to_dict()
        if "data" in data:  # skip lastUpdate
            history.append(data)
    return history

def update_weather_data_for_garden(uid, garden_id):
    garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
    garden_doc = garden_ref.get()
    if not garden_doc.exists:
        raise ValueError("Garden not found")

    garden = garden_doc.to_dict()
    location = garden.get("location")
    start_date = garden.get("startDate")
    if not location or "lat" not in location or "lon" not in location:
        raise ValueError("Invalid location")

    lat = location["lat"]
    lon = location["lon"]
    today = datetime.datetime.now(pytz.utc)

    last_doc = garden_ref.collection("weather_data").document("last_update").get()
    last_update = last_doc.to_dict().get("lastUpdate") if last_doc.exists else start_date
    last_date = datetime.datetime.fromisoformat(last_update)
    if last_date.tzinfo is None:
        last_date = last_date.replace(tzinfo=pytz.utc)

    if last_date >= today:
        return {"message": "Weather data already up to date"}

    start_str = last_date.strftime("%Y-%m-%d")
    end_str = today.strftime("%Y-%m-%d")

    url = (
        f"https://archive-api.open-meteo.com/v1/archive"
        f"?latitude={lat}&longitude={lon}"
        f"&start_date={start_str}&end_date={end_str}"
        f"&hourly=temperature_2m,relative_humidity_2m,pressure_msl,uv_index,weathercode"
        f"&timezone=UTC"
    )

    response = requests.get(url)
    response.raise_for_status()
    data = response.json()

    if "hourly" not in data:
        raise ValueError("No hourly data returned")

    hourly = data["hourly"]
    timestamps = hourly["time"]
    structured = {}

    for i, ts in enumerate(timestamps):
        dt = datetime.datetime.fromisoformat(ts)
        date_str = dt.strftime("%Y-%m-%d")
        hour_str = dt.strftime("%H:%M")

        if date_str not in structured:
            structured[date_str] = {"date": date_str, "data": []}

        structured[date_str]["data"].append({
            "time": hour_str,
            "temperature": hourly["temperature_2m"][i],
            "humidity": hourly["relative_humidity_2m"][i],
            "pressure": hourly["pressure_msl"][i],
            "uv_index": hourly["uv_index"][i],
            "weather_symbol": hourly["weathercode"][i]
        })

    for date, content in structured.items():
        doc_ref = garden_ref.collection("weather_data").document(date)
        existing = doc_ref.get()
        existing_data = existing.to_dict().get("data", []) if existing.exists else []

        existing_times = {d["time"] for d in existing_data}
        new_entries = [d for d in content["data"] if d["time"] not in existing_times]

        if new_entries:
            doc_ref.set({"date": date, "data": existing_data + new_entries}, merge=True)

    garden_ref.collection("weather_data").document("last_update").set({
        "lastUpdate": today.isoformat()
    })

    return {"message": "Weather data updated"}