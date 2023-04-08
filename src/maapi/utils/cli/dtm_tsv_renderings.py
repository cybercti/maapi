"""
Helper functions to extract fields for tabular output.
"""


def _render_tsv_entry_shop_listing_cc_header():
    return (
        'timestamp\tBIN\tType\tBrand\tIssuer\tShop\tPrice\tCurrency\tQuantity\tExpiry Date\tService Code\tBatch\tTrack1 Available\tTrack2 Available\t'
        'Name Available\tDOB Available\tSSN Available\tPhone Available\tOwner Name\tOwner Phone\tOwner Street Address\t'
        'Owner City\tOwner Region\tOwner Postal Code\tOwner Country'
    )
def _render_tsv_entry_shop_listing_cc(document):
    return (
        f'{document["timestamp"]}\t'
        f'{document["payment_card"].get("partial_number_prefix","")}\t'
        f'{document["payment_card"].get("type","")}\t'
        f'{document["payment_card"].get("brand","")}\t'
        f'{document["payment_card"].get("issuer","")}\t'
        f'{document["shop"]["name"]}\t{document["price"]}\t{document["currency"]}\t{document["item_qty"]}\t'
        f'{document["payment_card"]["expiry_date"]}\t{document["payment_card"].get("service_code","")}\t'
        f'{document["batch"]["name"]}\t'
        f'{document.get("data_availability",{}).get("track1_available","")}\t'
        f'{document.get("data_availability",{}).get("track2_available","")}'
        f'{document.get("data_availability",{}).get("name_available","")}'
        f'{document.get("data_availability",{}).get("dob_available","")}'
        f'{document.get("data_availability",{}).get("ssn_available","")}'
        f'{document.get("data_availability",{}).get("phone_available","")}'
        f'{document["payment_card"].get("owner",{}).get("identity",{}).get("name","")}' # Name
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("phone","")}' # Phone
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("street_address","")}' # Address
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("city","")}' # City
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("region","")}' # Region
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("postal_code","")}' # Postal Code
        f'{document["payment_card"].get("owner",{}).get("contact",{}).get("geo_location",{}).get("country_code","")}' # Country Code
    )
