import Foundation
import Testing

@testable import SecretBytes

@Suite struct ArchiveScalingTests {
	// MARK: Container encoding is linear, not quadratic

	/// `case .array(var items) = node.kind` used to leave the node's own
	/// payload referencing the same buffer, so every append copy-on-wrote the
	/// whole array: 16k elements took ~500 ms and the curve was 4× time per
	/// 2× length. This asserts the shape of the curve rather than a wall-clock
	/// threshold, so it stays meaningful on slower machines.
	///
	/// **Not run on the simulator.** A shared CI runner measured 37× here
	/// with the fix in place — worse than the ~16× a genuine quadratic
	/// regression produces, so the reading was environmental, not algorithmic
	/// (the same job took 13 minutes against 6 for its sibling leg). On real
	/// hardware the curve is clean: 2× elements costs 2.02× time, flat from
	/// 4k to 64k. A ratio test cannot survive a host that pauses the process
	/// mid-measurement, and no threshold rescues it — loosening the bar past
	/// 37× would stop detecting the defect. The property under test is a
	/// property of the algorithm, not of the platform, so measuring it where
	/// the clock is trustworthy loses nothing.
	@Test func largeArrayEncodingScalesLinearly() throws {
		#if targetEnvironment(simulator)
			try Test.cancel(
				"timing ratios are not measurable on a shared simulator host")
		#else
			try assertLinearScaling { count in
				try timeEncoding([UInt8](repeating: 0x11, count: count))
			}
		#endif
	}

	/// The identical hazard in `ArchiveKeyedContainer.put`, which was unpinned:
	/// deleting *its* `node.kind = .null` left the whole suite green while a
	/// `[String: Int]` degraded to a ~12× ratio for 4× the entries. Arrays and
	/// maps are separate code paths, and a dictionary is the larger container
	/// in practice.
	@Test func largeDictionaryEncodingScalesLinearly() throws {
		#if targetEnvironment(simulator)
			try Test.cancel(
				"timing ratios are not measurable on a shared simulator host")
		#else
			try assertLinearScaling { count in
				try timeEncoding(
					Dictionary(
						uniqueKeysWithValues: (0..<count).map {
							("k\($0)", $0)
						}))
			}
		#endif
	}

	// MARK: Keyed-container decode is linear, not quadratic

	/// Opted into integer wire keys, so lookups address `uint`/`negative` wire
	/// keys rather than text.
	private struct ArchiveIntegerKey: CodingKey, ArchiveIntegerCodingKey {
		let intValue: Int?
		var stringValue: String { "k\(intValue ?? 0)" }
		init(intValue: Int) { self.intValue = intValue }
		init?(stringValue: String) { nil }
	}

	/// Decodes the way downstream schemas actually do: `allKeys` then
	/// `decode(forKey:)` per key, so a per-key linear scan shows up here just
	/// as it would in real code, not only in a microbenchmark of `node(for:)`
	/// directly.
	private struct IntegerKeyedMap: Codable {
		var values: [Int: Int]
		init(values: [Int: Int]) { self.values = values }
		func encode(to encoder: Encoder) throws {
			var c = encoder.container(keyedBy: ArchiveIntegerKey.self)
			for (key, value) in values {
				try c.encode(value, forKey: ArchiveIntegerKey(intValue: key))
			}
		}
		init(from decoder: Decoder) throws {
			let c = try decoder.container(keyedBy: ArchiveIntegerKey.self)
			var result: [Int: Int] = [:]
			for key in c.allKeys {
				result[key.intValue!] = try c.decode(Int.self, forKey: key)
			}
			values = result
		}
	}

	/// `node(for:)` used to scan `entries` per key, so decoding an N-key map
	/// via `allKeys` + `decode(forKey:)` — the shape every keyed-container
	/// consumer uses — was O(N²). This is the integer-keyed path, addressed
	/// through `ArchiveKeyedDecodingContainer`'s integer branch.
	@Test func largeIntegerKeyedMapDecodingScalesLinearly() throws {
		#if targetEnvironment(simulator)
			try Test.cancel(
				"timing ratios are not measurable on a shared simulator host")
		#else
			try assertLinearScaling { count in
				let value = IntegerKeyedMap(
					values: Dictionary(
						uniqueKeysWithValues: (0..<count).map { ($0, $0) }))
				let encoded = try SecretArchive(encoding: value)
				return try timeDecoding(encoded, as: IntegerKeyedMap.self)
			}
		#endif
	}

	/// The text-keyed sibling: `[String: Int]`'s synthesized `init(from:)`
	/// drives the same `allKeys` + `decode(forKey:)` shape over the
	/// container's text branch.
	@Test func largeTextKeyedMapDecodingScalesLinearly() throws {
		#if targetEnvironment(simulator)
			try Test.cancel(
				"timing ratios are not measurable on a shared simulator host")
		#else
			try assertLinearScaling { count in
				let value = Dictionary(
					uniqueKeysWithValues: (0..<count).map { ("k\($0)", $0) })
				let encoded = try SecretArchive(encoding: value)
				return try timeDecoding(encoded, as: [String: Int].self)
			}
		#endif
	}

	@Test func hashedLookupRoundTripsSignedIntegerKeys() throws {
		let values = Dictionary(uniqueKeysWithValues: (-50..<50).map { ($0, $0 * 3) })
		let encoded = try SecretArchive(encoding: IntegerKeyedMap(values: values))
		#expect(try encoded.decode(IntegerKeyedMap.self).values == values)
	}

	/// Asserts the *shape* of the curve rather than a wall-clock threshold, so
	/// it survives a slow machine: quadratic growth at 4× the elements is ~16×
	/// the time, linear is ~4×, and the bar sits between them.
	///
	/// `timing` measures only the operation under test — encode or decode —
	/// with any setup (building the value, or the archive to decode from)
	/// done outside it.
	private func assertLinearScaling(
		sourceLocation: SourceLocation = #_sourceLocation,
		_ timing: (Int) throws -> Double
	) throws {
		_ = try timing(2000)  // warm up
		let small = try timing(8000)
		let large = try timing(32000)
		let floor = 0.0005  // ignore timer noise on very fast runs
		#expect(
			large < max(small, floor) * 10,
			"4× the elements took \(large / max(small, floor))× the time — the operation looks quadratic again",
			sourceLocation: sourceLocation)
	}

	private func timeEncoding<T: Encodable>(_ value: T) throws -> Double {
		let start = ProcessInfo.processInfo.systemUptime
		_ = try SecretArchive(encoding: value)
		return ProcessInfo.processInfo.systemUptime - start
	}

	private func timeDecoding<T: Decodable>(_ archive: SecretArchive, as type: T.Type) throws
		-> Double
	{
		let start = ProcessInfo.processInfo.systemUptime
		_ = try archive.decode(type)
		return ProcessInfo.processInfo.systemUptime - start
	}
}
