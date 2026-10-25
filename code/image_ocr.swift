import Foundation
import ImageIO
import PDFKit
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

guard let mode = CommandLine.arguments.dropFirst().first else {
    fputs("Expected an extraction mode.\n", stderr)
    exit(2)
}

let inputPaths = Array(CommandLine.arguments.dropFirst(2))

do {
    if mode == "images" {
        var recognizedImages: [[String]] = []
        for imagePath in inputPaths {
            let imageURL = URL(fileURLWithPath: imagePath)
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.usesLanguageCorrection = false
            try VNImageRequestHandler(url: imageURL).perform([request])

            recognizedImages.append(groupedTextLines(from: request.results ?? []))
        }
        let output = try JSONSerialization.data(withJSONObject: recognizedImages)
        FileHandle.standardOutput.write(output)
    } else if mode == "pdfs" {
        var extracted: [String] = []
        for path in inputPaths {
            guard let document = PDFDocument(url: URL(fileURLWithPath: path)) else {
                throw NSError(
                    domain: "EvidenceTextExtraction",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Unable to open PDF: \(path)"]
                )
            }
            extracted.append((0..<document.pageCount)
                .compactMap { document.page(at: $0)?.string }
                .joined(separator: "\n"))
        }
        let output = try JSONSerialization.data(withJSONObject: extracted)
        FileHandle.standardOutput.write(output)
    } else {
        fputs("Unsupported extraction mode: \(mode)\n", stderr)
        exit(2)
    }
} catch {
    fputs("Evidence text extraction failed: \(error)\n", stderr)
    exit(1)
}
