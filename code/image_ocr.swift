import Foundation
import ImageIO
import Vision

func groupedTextLines(
    from observations: [VNRecognizedTextObservation]
) -> [String] {
    let sortedObservations = observations.sorted {
        $0.boundingBox.midY > $1.boundingBox.midY
    }
    var groups: [[VNRecognizedTextObservation]] = []

    for observation in sortedObservations {
        if let lastGroup = groups.indices.last,
           abs(
               groups[lastGroup].map(\.boundingBox.midY).reduce(0, +)
                   / CGFloat(groups[lastGroup].count)
                   - observation.boundingBox.midY
           ) <= 0.008 {
            groups[lastGroup].append(observation)
        } else {
            groups.append([observation])
        }
    }

    return groups.map { group in
        group
            .sorted { $0.boundingBox.minX < $1.boundingBox.minX }
            .compactMap { $0.topCandidates(1).first?.string }
            .joined(separator: " ")
    }
}

let imagePaths = Array(CommandLine.arguments.dropFirst())
var recognizedImages: [[String]] = []

do {
    for imagePath in imagePaths {
        let imageURL = URL(fileURLWithPath: imagePath)
        let request = VNRecognizeTextRequest()
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        try VNImageRequestHandler(url: imageURL).perform([request])

        recognizedImages.append(groupedTextLines(from: request.results ?? []))
    }

    let output = try JSONSerialization.data(withJSONObject: recognizedImages)
    FileHandle.standardOutput.write(output)
} catch {
    fputs("Vision OCR failed: \(error)\n", stderr)
    exit(1)
}
