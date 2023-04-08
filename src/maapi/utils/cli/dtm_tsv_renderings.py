"""
Helper functions to extract fields for tabular output.
"""


def render_tsv_entry_shop_listing_cc_header() -> str:
    """
    Return a header row for CC shop listing.
    """
    return (
        'timestamp\tShop\tBIN\tFull Number\tType\tBrand\tIssuer\tProduct\tPrice\tCurrency\tQuantity\tExpiry Date\t'
        'Service Code\tBatch\tTrack1 Available\tTrack2 Available\tName Available\tDOB Available\tSSN Available\t'
        'Phone Available\tOwner Name\tOwner Phone\tOwner Street Address\t'
        'Owner City\tOwner Region\tOwner Postal Code\tOwner Country Code'
    )

def render_tsv_entry_shop_listing_cc(document) -> str:
    """
    Return a row representation ot values, deliminited by tabs.
    """
    return (
        f'{document["timestamp"]}\t'
        f'{document["shop"].get("name")}\t'
        f'{document["payment_card"].get("partial_number_prefix","")}\t'
        f'{document["payment_card"].get("full_number","")}\t'
        f'{document["payment_card"].get("type","")}\t'
        f'{document["payment_card"].get("brand","")}\t'
        f'{document["payment_card"].get("issuer","")}\t'
        f'{document["payment_card"].get("product","")}\t'
        f'{document["price"]}\t'
        f'{document["currency"]}\t'
        f'{document["item_qty"]}\t'
        f'{document["payment_card"].get("expiry_date","")}\t'
        f'{document["payment_card"].get("service_code","")}\t'
        f'{document["batch"].get("name")}\t'
        f'{document.get("data_availability",{}).get("track1_available","")}\t'
        f'{document.get("data_availability",{}).get("track2_available","")}\t'
        f'{document.get("data_availability",{}).get("name_available","")}\t'
        f'{document.get("data_availability",{}).get("dob_available","")}\t'
        f'{document.get("data_availability",{}).get("ssn_available","")}\t'
        f'{document.get("data_availability",{}).get("phone_available","")}\t'
        f'{document["payment_card"].get("owner",{}).get("identity",{}).get("name","")}\t'
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("phone","")}\t'
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("street_address","")}\t'
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("city","")}\t'
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("region","")}\t'
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("postal_code","")}\t'
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("country_code","")}'
    )
