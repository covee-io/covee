// Draws the Covee logo and writes every file made from it:
//   native/apple/App/Assets.xcassets/AppIcon.appiconset  Mac sizes and the iPhone icon
//   docs/brand/covee-icon.png, covee-mark.svg, covee-logo.svg
//   internal/identity/assets/covee-mark.svg (inlined into the sign-in pages)
//   docs/brand/covee-favicon-64.png (browser tab icon; deploy/headscale's patch carries a copy)
//   native/apple/App/Assets.xcassets/MenuBar{On,Off}.imageset (the Mac menu bar icon)
//
//   xcrun swift scripts/make_brand.swift
//
// The mark is a "C" for Covee drawn as a ring that is nearly closed: a device
// (the centre dot) inside the network's own ring, with two more devices
// completing the circle. One set of numbers below drives both the PNGs and SVGs.
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()

// Geometry in tile units: the tile is 824 wide, as in Apple's 1024 Mac icon grid.
let tile: CGFloat = 824
let corner: CGFloat = 185
let centre = CGPoint(x: 412, y: 412)
let ringRadius: CGFloat = 214
let ringWidth: CGFloat = 78
let ringGapDegrees: CGFloat = 58   // the ring runs from +58 degrees round to -58 degrees
let nodeDegrees: CGFloat = 31      // the two outer devices sit on the ring at +/-31 degrees
let nodeRadius: CGFloat = 46
let hubRadius: CGFloat = 54
// Colours: aqua to royal blue, like water in a sheltered bay.
let gradient: [(stop: CGFloat, hex: UInt32)] = [(0, 0x22C3D6), (0.55, 0x2563EB), (1, 0x2A3FC9)]
let gradientFrom = CGPoint(x: 60, y: 800), gradientTo = CGPoint(x: 780, y: 20)   // tile units, y up
let ink: UInt32 = 0x1F2A44

func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
}

func point(_ degrees: CGFloat, _ radius: CGFloat) -> CGPoint {
    let a = degrees * .pi / 180
    return CGPoint(x: centre.x + radius * cos(a), y: centre.y + radius * sin(a))
}

/// Draws the white mark in tile units.
func drawMark(_ ctx: CGContext, colour: CGColor) {
    ctx.setStrokeColor(colour)
    ctx.setFillColor(colour)
    ctx.setLineWidth(ringWidth)
    ctx.setLineCap(.round)
    ctx.addArc(center: centre, radius: ringRadius, startAngle: ringGapDegrees * .pi / 180, endAngle: (360 - ringGapDegrees) * .pi / 180, clockwise: false)
    ctx.strokePath()
    for (p, r) in [(point(nodeDegrees, ringRadius), nodeRadius), (point(-nodeDegrees, ringRadius), nodeRadius), (centre, hubRadius)] {
        ctx.fillEllipse(in: CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r))
    }
}

func drawGradient(_ ctx: CGContext, _ space: CGColorSpace) {
    let g = CGGradient(colorsSpace: space, colors: gradient.map { rgb($0.hex) } as CFArray, locations: gradient.map(\.stop))!
    ctx.drawLinearGradient(g, start: gradientFrom, end: gradientTo, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
}

enum Style { case mac, ios, favicon }

/// Renders the icon at pixels x pixels. Mac icons are a rounded tile with a
/// shadow inside a transparent 1024 grid; the iPhone icon fills the whole square
/// without transparency, and iOS rounds it.
func icon(_ style: Style, pixels: Int) -> CGImage {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let alpha = style == .ios ? CGImageAlphaInfo.noneSkipLast : CGImageAlphaInfo.premultipliedLast
    let ctx = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0, space: space, bitmapInfo: alpha.rawValue)!
    ctx.interpolationQuality = .high
    let scale = CGFloat(pixels) / (style == .mac ? 1024 : tile)
    ctx.scaleBy(x: scale, y: scale)
    if style == .mac {
        ctx.translateBy(x: 100, y: 100)
        let shape = CGPath(roundedRect: CGRect(x: 0, y: 0, width: tile, height: tile), cornerWidth: corner, cornerHeight: corner, transform: nil)
        ctx.saveGState()
        // Shadows are measured in output pixels, not in the scaled units.
        ctx.setShadow(offset: CGSize(width: 0, height: -10 * scale), blur: 24 * scale, color: rgb(0x000000, 0.28))
        ctx.addPath(shape)
        ctx.setFillColor(rgb(0x2563EB))
        ctx.fillPath()
        ctx.restoreGState()
        ctx.addPath(shape)
        ctx.clip()
    } else if style == .favicon {
        // A browser tab icon: the rounded tile fills the square, no shadow.
        ctx.addPath(CGPath(roundedRect: CGRect(x: 0, y: 0, width: tile, height: tile), cornerWidth: corner, cornerHeight: corner, transform: nil))
        ctx.clip()
    }
    drawGradient(ctx, space)
    drawMark(ctx, colour: rgb(0xFFFFFF))
    return ctx.makeImage()!
}

/// The bare mark in black for the Mac menu bar, which tints template images
/// itself. alpha dims the "off" state.
func menuBarIcon(pixels: Int, alpha: CGFloat) -> CGImage {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let ctx = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0, space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    // The mark's own extent in tile units, centred with a little room.
    let box = CGRect(x: 140, y: 150, width: 540, height: 524)
    let scale = CGFloat(pixels) / max(box.width, box.height)
    ctx.scaleBy(x: scale, y: scale)
    ctx.translateBy(x: -box.minX + (max(box.width, box.height) - box.width) / 2, y: -box.minY + (max(box.width, box.height) - box.height) / 2)
    drawMark(ctx, colour: rgb(0x000000, alpha))
    return ctx.makeImage()!
}

func writePNG(_ image: CGImage, _ url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    guard let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else { throw CocoaError(.fileWriteUnknown) }
    CGImageDestinationAddImage(dest, image, nil)
    guard CGImageDestinationFinalize(dest) else { throw CocoaError(.fileWriteUnknown) }
}

func write(_ text: String, _ url: URL) throws {
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try text.write(to: url, atomically: true, encoding: .utf8)
}

// SVG uses y down, so a point's y is flipped within the tile.
func svgMark(fill: String, offset: CGPoint = .zero) -> String {
    func f(_ v: CGFloat) -> String { String(format: "%.1f", v) }
    func p(_ q: CGPoint) -> (String, String) { (f(q.x + offset.x), f(tile - q.y + offset.y)) }
    let (sx, sy) = p(point(ringGapDegrees, ringRadius)), (ex, ey) = p(point(-ringGapDegrees, ringRadius))
    var out = "<path d=\"M \(sx) \(sy) A \(f(ringRadius)) \(f(ringRadius)) 0 1 0 \(ex) \(ey)\" fill=\"none\" stroke=\"\(fill)\" stroke-width=\"\(f(ringWidth))\" stroke-linecap=\"round\"/>\n"
    for (q, r) in [(point(nodeDegrees, ringRadius), nodeRadius), (point(-nodeDegrees, ringRadius), nodeRadius), (centre, hubRadius)] {
        let (x, y) = p(q)
        out += "<circle cx=\"\(x)\" cy=\"\(y)\" r=\"\(f(r))\" fill=\"\(fill)\"/>\n"
    }
    return out
}

func svgGradient(id: String) -> String {
    func hex(_ v: UInt32) -> String { String(format: "#%06X", v) }
    let stops = gradient.map { "<stop offset=\"\($0.stop)\" stop-color=\"\(hex($0.hex))\"/>" }.joined()
    return "<linearGradient id=\"\(id)\" gradientUnits=\"userSpaceOnUse\" x1=\"\(gradientFrom.x)\" y1=\"\(tile - gradientFrom.y)\" x2=\"\(gradientTo.x)\" y2=\"\(tile - gradientTo.y)\">\(stops)</linearGradient>"
}

let icons = root.appendingPathComponent("native/apple/App/Assets.xcassets/AppIcon.appiconset")
var images: [[String: String]] = []
for points in [16, 32, 128, 256, 512] {
    for factor in [1, 2] {
        let name = "mac-\(points)@\(factor)x.png"
        try writePNG(icon(.mac, pixels: points * factor), icons.appendingPathComponent(name))
        images.append(["idiom": "mac", "size": "\(points)x\(points)", "scale": "\(factor)x", "filename": name])
    }
}
try writePNG(icon(.ios, pixels: 1024), icons.appendingPathComponent("ios-1024.png"))
images.append(["idiom": "universal", "platform": "ios", "size": "1024x1024", "filename": "ios-1024.png"])
let contents: [String: Any] = ["images": images, "info": ["author": "xcode", "version": 1]]
try write(String(data: JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)! + "\n", icons.appendingPathComponent("Contents.json"))
try write("{\n  \"info\" : {\n    \"author\" : \"xcode\",\n    \"version\" : 1\n  }\n}\n", icons.deletingLastPathComponent().appendingPathComponent("Contents.json"))

for (name, alpha) in [("MenuBarOn", CGFloat(1)), ("MenuBarOff", CGFloat(0.45))] {
    let set = icons.deletingLastPathComponent().appendingPathComponent(name + ".imageset")
    try writePNG(menuBarIcon(pixels: 18, alpha: alpha), set.appendingPathComponent(name + ".png"))
    try writePNG(menuBarIcon(pixels: 36, alpha: alpha), set.appendingPathComponent(name + "@2x.png"))
    let contents: [String: Any] = ["images": [["idiom": "mac", "scale": "1x", "filename": name + ".png"], ["idiom": "mac", "scale": "2x", "filename": name + "@2x.png"]],
                                   "info": ["author": "xcode", "version": 1], "properties": ["template-rendering-intent": "template"]]
    try write(String(data: JSONSerialization.data(withJSONObject: contents, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)! + "\n", set.appendingPathComponent("Contents.json"))
}

let brand = root.appendingPathComponent("docs/brand")
try writePNG(icon(.mac, pixels: 1024), brand.appendingPathComponent("covee-icon.png"))
try writePNG(icon(.favicon, pixels: 64), brand.appendingPathComponent("covee-favicon-64.png"))
let header = "<!-- Generated by scripts/make_brand.swift; edit the numbers there, not this file. -->\n"
try write(header + "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 \(Int(tile)) \(Int(tile))\" width=\"\(Int(tile))\" height=\"\(Int(tile))\">\n<defs>\(svgGradient(id: "covee"))</defs>\n<rect width=\"\(Int(tile))\" height=\"\(Int(tile))\" rx=\"\(Int(corner))\" fill=\"url(#covee)\"/>\n" + svgMark(fill: "#FFFFFF") + "</svg>\n",
          brand.appendingPathComponent("covee-mark.svg"))
// The sign-in pages inline the mark; their policy allows no image or font requests.
try write("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 \(Int(tile)) \(Int(tile))\" aria-hidden=\"true\" focusable=\"false\"><defs>\(svgGradient(id: "covee-mark-gradient"))</defs><rect width=\"\(Int(tile))\" height=\"\(Int(tile))\" rx=\"\(Int(corner))\" fill=\"url(#covee-mark-gradient)\"/>" + svgMark(fill: "#FFFFFF").replacingOccurrences(of: "\n", with: "") + "</svg>\n",
          root.appendingPathComponent("internal/identity/assets/covee-mark.svg"))
// The logo: the tile beside the word Covee.
let wordX = Int(tile) + 120
try write(header + "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 3000 \(Int(tile))\" width=\"750\" height=\"\(Int(tile) / 4)\">\n<defs>\(svgGradient(id: "covee"))</defs>\n<rect width=\"\(Int(tile))\" height=\"\(Int(tile))\" rx=\"\(Int(corner))\" fill=\"url(#covee)\"/>\n" + svgMark(fill: "#FFFFFF") +
          "<text x=\"\(wordX)\" y=\"600\" font-family=\"SF Pro Display, -apple-system, 'Helvetica Neue', Arial, sans-serif\" font-weight=\"600\" font-size=\"560\" letter-spacing=\"-12\" fill=\(String(format: "\"#%06X\"", ink))>Covee</text>\n</svg>\n",
          brand.appendingPathComponent("covee-logo.svg"))
print("Wrote \(images.count) app icon images, docs/brand/covee-icon.png, covee-mark.svg, covee-logo.svg and internal/identity/assets/covee-mark.svg")
