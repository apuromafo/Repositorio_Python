import requests
import json
import time

def download_json(url):
    """
    Downloads a JSON file from the given URL.

    Args:
        url (str): The URL of the JSON file.

    Returns:
        dict: The parsed JSON content, or None if an error occurs.
    """
    print(f"Downloading JSON from: {url}")
    try:
        # Use a raw content URL for GitHub files
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        response = requests.get(raw_url, timeout=10) # Set a timeout for the request
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.HTTPError as err_http:
        print(f"HTTP error occurred: {err_http}")
    except requests.exceptions.ConnectionError as err_conn:
        print(f"Connection error occurred: {err_conn}")
    except requests.exceptions.Timeout as err_timeout:
        print(f"Timeout error occurred: {err_timeout}")
    except requests.exceptions.RequestException as err:
        print(f"An unexpected error occurred during request: {err}")
    except json.JSONDecodeError as err_json:
        print(f"Error decoding JSON: {err_json}")
    return None

def is_url_online(url):
    """
    Checks if a given URL is online by making a HEAD request.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is reachable and returns a success status (2xx or 3xx),
              False otherwise.
    """
    if not url:
        return False
    print(f"Checking URL: {url}")
    try:
        # Use HEAD request for efficiency as we only need the status code
        # Allow redirects (e.g., HTTP to HTTPS)
        response = requests.head(url, timeout=5, allow_redirects=True)
        # Consider 2xx (success) and 3xx (redirection) as online
        return 200 <= response.status_code < 400
    except requests.exceptions.ConnectionError:
        print(f"Connection error for {url}")
    except requests.exceptions.Timeout:
        print(f"Timeout for {url}")
    except requests.exceptions.RequestException as e:
        print(f"Error checking {url}: {e}")
    return False

def process_and_validate_urls(data):
    """
    Processes the downloaded data, validates URLs, and structures the output.

    Args:
        data (list): A list of dictionaries from the downloaded JSON.

    Returns:
        list: A new list of dictionaries with 'is_online' status,
              sorted by online status (online first).
    """
    if not data:
        return []

    validated_entries = []
    total_urls = len(data)
    for i, entry in enumerate(data):
        url = entry.get("url")
        name = entry.get("name")
        collection = entry.get("collection", [])

        print(f"Processing entry {i+1}/{total_urls}: {name} ({url})")

        is_online_status = False
        if url and isinstance(url, str):
            is_online_status = is_url_online(url)
        else:
            print(f"Skipping validation for entry '{name}' due to missing or invalid URL.")

        validated_entry = {
            "url": url,
            "name": name,
            "collection": collection,
            "is_online": is_online_status
        }
        validated_entries.append(validated_entry)

        # Optional: Add a small delay to avoid overwhelming servers
        # time.sleep(0.1)

    # Sort: online URLs first (True > False in boolean comparison)
    validated_entries.sort(key=lambda x: x["is_online"], reverse=True)

    return validated_entries

def save_json(data, filename):
    """
    Saves data to a JSON file.

    Args:
        data (list): The data to save.
        filename (str): The name of the file to save to.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"Successfully saved validated data to {filename}")
    except IOError as e:
        print(f"Error saving file {filename}: {e}")

if __name__ == "__main__":
    github_json_url = "https://github.com/OWASP/OWASP-VWAD/blob/master/src/data/collection.json"
    output_filename = "validated.json"

    # Step 1: Download the content
    collection_data = download_json(github_json_url)

    if collection_data:
        # Step 2 & 3 & 4: Process, validate, and structure
        validated_result = process_and_validate_urls(collection_data)

        # Step 5 & 6: Save the new JSON
        save_json(validated_result, output_filename)
    else:
        print("Failed to download or parse the initial JSON data. Exiting.")
