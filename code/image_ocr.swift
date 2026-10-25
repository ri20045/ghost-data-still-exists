import Foundation
import ImageIO
import Vision

let imagePaths = Array(CommandLine.arguments.dropFirst())
var recognizedImages: [[String]] = []

do {
    for imagePath in imagePaths {
        let imageURL = URL(fileURLWithPath: imagePath)
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        try VNImageRequestHandler(url: imageURL).perform([request])

        let lines = (request.results ?? [])
            .sorted {
                if abs($0.boundingBox.midY - $1.boundingBox.midY) > 0.01 {
                    return $0.boundingBox.midY > $1.boundingBox.midY
                }
                return $0.boundingBox.minX < $1.boundingBox.minX
            }
            .compactMap { $0.topCandidates(1).first?.string }
        recognizedImages.append(lines)
    }

    let output = try JSONSerialization.data(withJSONObject: recognizedImages)
    FileHandle.standardOutput.write(output)
} catch {
    fputs("Vision OCR failed: \(error)\n", stderr)
    exit(1)
}
