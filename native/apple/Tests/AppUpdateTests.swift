import XCTest
import Foundation

final class AppUpdateTests: XCTestCase {
    private func release(tag: String, assets: String = #"[{"name":"Covee.dmg","browser_download_url":"https://github.com/covee-io/covee/releases/download/v0.1.3/Covee.dmg"}]"#,
                         page: String = "https://github.com/covee-io/covee/releases/tag/v0.1.3") -> Data {
        Data(#"{"tag_name":"\#(tag)","html_url":"\#(page)","draft":false,"assets":\#(assets)}"#.utf8)
    }

    func testVersionsCompareNumericallyNotAsText() throws {
        XCTAssertLessThan(try XCTUnwrap(AppVersion("0.1.9")), try XCTUnwrap(AppVersion("v0.1.10")))
        XCTAssertLessThan(try XCTUnwrap(AppVersion("0.9")), try XCTUnwrap(AppVersion("1.0.0")))
        XCTAssertEqual(try XCTUnwrap(AppVersion("v1.2")), try XCTUnwrap(AppVersion("1.2.0")))
        for tag in ["", "v", "1..2", "1.2-beta", "latest", "-1.0"] {
            XCTAssertNil(AppVersion(tag), tag)
        }
    }

    func testANewerReleaseIsOfferedWithItsDiskImage() throws {
        let newest = try AppRelease.decode(release(tag: "v0.1.3"))
        guard case .available(let found, current: "0.1.2") = AppUpdateResult.compare(newest, current: "0.1.2") else {
            return XCTFail("0.1.3 should be offered over 0.1.2")
        }
        XCTAssertEqual(found.version, "0.1.3")
        XCTAssertEqual(found.downloadURL?.lastPathComponent, "Covee.dmg")
    }

    func testTheSameOrAnOlderReleaseIsUpToDate() throws {
        let newest = try AppRelease.decode(release(tag: "v0.1.2"))
        XCTAssertEqual(AppUpdateResult.compare(newest, current: "0.1.2"), .upToDate(current: "0.1.2"))
        XCTAssertEqual(AppUpdateResult.compare(newest, current: "0.2.0"), .upToDate(current: "0.2.0"))
    }

    func testLinksOffGitHubAreNotFollowed() throws {
        let elsewhere = #"[{"name":"Covee.dmg","browser_download_url":"https://example.com/Covee.dmg"}]"#
        XCTAssertNil(try AppRelease.decode(release(tag: "v0.1.3", assets: elsewhere)).downloadURL)
        XCTAssertNil(try AppRelease.decode(release(tag: "v0.1.3", assets: "[]")).downloadURL)
        XCTAssertThrowsError(try AppRelease.decode(release(tag: "v0.1.3", page: "https://example.com/release")))
        XCTAssertThrowsError(try AppRelease.decode(release(tag: "nightly")))
    }
}
