import json

def display_validation_results(filename="002_validated.json"):
    """
    Loads the validated.json file and displays the online and offline URLs in a table.
    This version does not truncate the Name and URL fields.

    Args:
        filename (str): The name of the JSON file to load.
    """
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found. Please ensure your script has generated it.")
        return
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from '{filename}': {e}")
        return

    online_urls = [entry for entry in data if entry.get("is_online")]
    offline_urls = [entry for entry in data if not entry.get("is_online")]

    print("\n" + "="*80) # Increased width for better display
    print("           URL Validation Results")
    print("="*80 + "\n")

    if online_urls:
        print("## URLs Online\n")
        # Adjust column widths as needed based on your longest names/URLs
        # These are example widths, you might need to increase them further
        print("{:<5} {:<40} {:<80}".format("No.", "Name", "URL"))
        print("-" * 125) # Adjust separator line length
        for i, entry in enumerate(online_urls):
            name = entry.get("name", "N/A")
            url = entry.get("url", "N/A")
            print("{:<5} {:<40} {:<80}".format(i + 1, name, url))
        print("\n")
    else:
        print("No URLs online found.\n")

    if offline_urls:
        print("## URLs Offline\n")
        # Adjust column widths as needed
        print("{:<5} {:<40} {:<80}".format("No.", "Name", "URL"))
        print("-" * 125) # Adjust separator line length
        for i, entry in enumerate(offline_urls):
            name = entry.get("name", "N/A")
            url = entry.get("url", "N/A")
            print("{:<5} {:<40} {:<80}".format(i + 1, name, url))
        print("\n")
    else:
        print("No URLs offline found.\n")

    print("="*80)

if __name__ == "__main__":
    display_validation_results("002_validated.json")