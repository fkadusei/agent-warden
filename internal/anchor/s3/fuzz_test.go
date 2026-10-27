package s3

import (
	"testing"
)

// FuzzParseListing feeds arbitrary bytes to the version-listing parser, which
// reads whatever the store returns. Nothing may panic, and every entry it
// accepts must have a name and a version ID.
func FuzzParseListing(f *testing.F) {
	f.Add([]byte(`<ListVersionsResult><IsTruncated>false</IsTruncated>` +
		`<DeleteMarker><Key>p/c/1.json</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest><LastModified>2026-10-27T10:00:01.000Z</LastModified></DeleteMarker>` +
		`<Version><Key>p/c/1.json</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest><LastModified>2026-10-27T10:00:00.000Z</LastModified></Version>` +
		`</ListVersionsResult>`))
	f.Add([]byte(`<ListVersionsResult><IsTruncated>true</IsTruncated><NextKeyMarker>k</NextKeyMarker><NextVersionIdMarker>v</NextVersionIdMarker></ListVersionsResult>`))
	f.Add([]byte(`<Version><Key></Key></Version>`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, vs, err := parseListing(data)
		if err != nil {
			return
		}
		for _, v := range vs {
			if v.Key == "" || v.VersionID == "" {
				t.Fatalf("accepted an incomplete entry: %+v", v)
			}
		}
	})
}
