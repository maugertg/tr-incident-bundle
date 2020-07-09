from threatresponse import ThreatResponse

def make_incident(client):
    bundle = {
        "type": "bundle",
        "source": "Incident Demo",
        "sightings": [
            {
                "description": "Sighting Description goes in the Description Column",
                "schema_version": "1.0.17",
                "relations": [
                    {
                        "origin": "Incident Demo",
                        "relation": "Downloaded_From",
                        "source": {
                            "value": "10281a188a26dbb10562bdc6f5467abad4b0e7fe73672b48a11fdd55819f81f3",
                            "type": "sha256",
                        },
                        "related": {"value": "112.121.153.187", "type": "ip"},
                    }
                ],
                "observables": [
                    {
                        "value": "10281a188a26dbb10562bdc6f5467abad4b0e7fe73672b48a11fdd55819f81f3",
                        "type": "sha256",
                    }
                ],
                "type": "sighting",
                "source": "Incident Demo",
                "targets": [
                    {
                        "type": "endpoint",
                        "observables": [
                            {"value": "10.10.10.10", "type": "ip"},
                            {"value": "Win10-Host01", "type": "hostname"},
                            {"value": "00:0c:29:38:21:f6", "type": "mac_address"},
                        ],
                        "observed_time": {"start_time": "2020-07-06T13:31:17.245Z"},
                    }
                ],
                "internal": True,
                "source_uri": "https://example.com",
                "id": "transient:incident-demo-sighting-9a4b33d5-abad-4c80-9f46-30ed3206a53c",
                "external_ids": [
                    "incident-demo-sighting-9a4b33d5-abad-4c80-9f46-30ed3206a53c"
                ],
                "count": 1,
                "confidence": "High",
                "observed_time": {"start_time": "2020-07-06T13:31:17.245Z"},
                "sensor": "Network Sensor",
            }
        ],
        "incidents": [
            {
                "confidence": "High",
                "incident_time": {"opened": "2020-07-07T01:01:01.000Z"},
                "status": "New",
                "short_description": "This is a test incident short description that is shown in the Description field on the Incidents page",
                "schema_version": "1.0.17",
                "title": "New Incident Title",
                "type": "incident",
                "description": "Description of the new incident being created is shown in the Summary tab",
                "id": "transient:incident-demo-incident-31305568847774c2ff82d3eb9309ac7d55eb5265f505e6b8924e80ac4fa62c94",
                "external_ids": [
                    "incident-demo-incident-31305568847774c2ff82d3eb9309ac7d55eb5265f505e6b8924e80ac4fa62c94"
                ],
            }
        ],
        "indicators": [
            {
                "description": "Doc.Downloader.Donoff::100.sbx.tg",
                "tags": ["malware"],
                "valid_time": {},
                "producer": "Incident Demo",
                "schema_version": "1.0.17",
                "type": "indicator",
                "short_description": "Doc.Downloader.Donoff::100.sbx.tg",
                "title": "Doc.Downloader.Donoff::100.sbx.tg",
                "id": "transient:incident-demo-indicator-8a3011cd-1774-4008-8080-9bd65e4a71f0",
                "external_ids": [
                    "incident-demo-indicator-8a3011cd-1774-4008-8080-9bd65e4a71f0"
                ],
                "tlp": "amber",
                "confidence": "High",
            }
        ],
        "relationships": [
            {
                "type": "relationship",
                "source_ref": "transient:incident-demo-sighting-9a4b33d5-abad-4c80-9f46-30ed3206a53c",
                "target_ref": "transient:incident-demo-incident-31305568847774c2ff82d3eb9309ac7d55eb5265f505e6b8924e80ac4fa62c94",
                "relationship_type": "member-of",
                "external_ids": [
                    "incident-demo-c22a4269ae07827cb1c3ab8ebdbdbd5b722bd2e52afdecc8b5dd1a76b6289323"
                ],
            },
            {
                "type": "relationship",
                "source_ref": "transient:incident-demo-sighting-9a4b33d5-abad-4c80-9f46-30ed3206a53c",
                "target_ref": "transient:incident-demo-indicator-8a3011cd-1774-4008-8080-9bd65e4a71f0",
                "relationship_type": "sighting-of",
                "external_ids": [
                    "incident-demo-36b8bdc33a1260be054d362391705dffcce35fe039d25fd6765f593d0173a7b4"
                ],
            },
            {
                "type": "relationship",
                "source_ref": "transient:incident-demo-incident-31305568847774c2ff82d3eb9309ac7d55eb5265f505e6b8924e80ac4fa62c94",
                "target_ref": "transient:incident-demo-indicator-8a3011cd-1774-4008-8080-9bd65e4a71f0",
                "relationship_type": "sighting-of",
                "external_ids": [
                    "incident-demo-a08e3a6eebee24a5d1233a19eb8d15952b2fbf7309fc8f5d8476f8932534b5a7"
                ],
            },
        ],
    }


    params = {"external-key-prefixes": "incident-demo-"}

    response = client.private_intel.bundle.import_.post(payload=bundle, params=params)

    print(response)


def main():

    client_id = ''
    client_password = ''

    client = ThreatResponse(
        client_id=client_id,
        client_password=client_password,
        region='us'
    )

    make_incident(client)

if __name__ == '__main__':
    main()