use memchr::memchr_iter;
use rayon::prelude::*;

use crate::taint::{self, ScanResult, ProgressFn};
use crate::taint::chunk_scan;
use crate::taint::merge;

/// Parallel version of scan_unified.
/// Falls back to single-threaded for small files.
pub fn scan_unified_parallel(
    data: &[u8],
    data_only: bool,
    no_prune: bool,
    skip_strings: bool,
    progress_fn: Option<ProgressFn>,
    num_chunks: usize,
) -> anyhow::Result<ScanResult> {
    // Small files or single chunk: fall back to single-threaded
    if data.len() < 10 * 1024 * 1024 || num_chunks <= 1 {
        return taint::scan_unified(data, data_only, no_prune, skip_strings, progress_fn);
    }

    let format = taint::gumtrace_parser::detect_format(data);

    // Phase 0: Split and count lines
    let chunks_meta = split_into_chunks(data, num_chunks);

    // LINE_MASK safety check: 29-bit line number limit (bits 29-31 reserved for flags)
    let total_lines: u32 = chunks_meta.iter().map(|c| c.line_count).sum();
    if total_lines > crate::taint::scanner::LINE_MASK {
        anyhow::bail!(
            "文件行数 {} 超过当前支持的最大值 {}（约 5.36 亿行）。",
            total_lines,
            crate::taint::scanner::LINE_MASK,
        );
    }

    if let Some(ref cb) = progress_fn {
        cb(0, data.len());
    }

    // Phase 1: Parallel chunk scanning
    let chunk_results: Vec<_> = chunks_meta
        .par_iter()
        .map(|meta| {
            chunk_scan::scan_chunk(
                data,
                meta.start_byte,
                meta.end_byte,
                meta.start_line,
                format,
                data_only,
                no_prune,
                skip_strings,
            )
        })
        .collect();

    if let Some(ref cb) = progress_fn {
        cb(data.len() * 2 / 3, data.len());
    }

    // Phase 2: Sequential merge
    let result = merge::merge_all_chunks(chunk_results, format, data_only);

    if let Some(ref cb) = progress_fn {
        cb(data.len(), data.len());
    }

    Ok(result)
}

/// Metadata for a chunk of the file.
pub struct ChunkMeta {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: u32,
    pub line_count: u32,
}

/// Split data into N chunks at newline boundaries.
/// Phase 0: uses parallel memchr to count lines per chunk.
pub fn split_into_chunks(data: &[u8], n: usize) -> Vec<ChunkMeta> {
    let n = n.max(1);
    let len = data.len();
    if len == 0 {
        return vec![ChunkMeta {
            start_byte: 0,
            end_byte: 0,
            start_line: 0,
            line_count: 0,
        }];
    }

    // 1. Determine raw byte boundaries, adjusting to nearest newline
    let chunk_size = len / n;
    let mut boundaries = Vec::with_capacity(n + 1);
    boundaries.push(0usize);

    for i in 1..n {
        let raw = i * chunk_size;
        // Find next newline after raw boundary
        let adjusted = match memchr::memchr(b'\n', &data[raw..]) {
            Some(pos) => raw + pos + 1, // start of next line
            None => len,
        };
        if adjusted < len && adjusted != *boundaries.last().unwrap() {
            boundaries.push(adjusted);
        }
    }
    boundaries.push(len);
    boundaries.dedup();

    // 2. Count lines per chunk (parallel using rayon)
    use rayon::prelude::*;
    let line_counts: Vec<u32> = boundaries
        .windows(2)
        .collect::<Vec<_>>()
        .par_iter()
        .map(|window| {
            let start = window[0];
            let end = window[1];
            let chunk_data = &data[start..end];
            let newline_count = memchr_iter(b'\n', chunk_data).count() as u32;
            // If this is the LAST chunk and doesn't end with newline, there's one more line
            if end == len && !chunk_data.is_empty() && *chunk_data.last().unwrap() != b'\n' {
                newline_count + 1
            } else {
                newline_count
            }
        })
        .collect();

    // 3. Compute prefix sums for global line offsets
    let mut chunks = Vec::with_capacity(line_counts.len());
    let mut cumulative_lines = 0u32;
    for (i, window) in boundaries.windows(2).enumerate() {
        chunks.push(ChunkMeta {
            start_byte: window[0],
            end_byte: window[1],
            start_line: cumulative_lines,
            line_count: line_counts[i],
        });
        cumulative_lines += line_counts[i];
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_chunks_basic() {
        let data = b"line0\nline1\nline2\nline3\nline4\n";
        let chunks = split_into_chunks(data, 2);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].start_byte, 0);
        assert_eq!(chunks[1].end_byte, data.len());
        assert_eq!(chunks[0].start_line, 0);
        assert_eq!(chunks[1].start_line, chunks[0].line_count);
        let total: u32 = chunks.iter().map(|c| c.line_count).sum();
        assert_eq!(total, 5);
    }

    #[test]
    fn test_split_chunks_single() {
        let data = b"line0\nline1\n";
        let chunks = split_into_chunks(data, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].start_byte, 0);
        assert_eq!(chunks[0].end_byte, data.len());
        assert_eq!(chunks[0].line_count, 2);
    }

    #[test]
    fn test_split_chunks_more_than_lines() {
        let data = b"a\nb\n";
        let chunks = split_into_chunks(data, 10);
        assert!(chunks.len() <= 2);
        let total: u32 = chunks.iter().map(|c| c.line_count).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn test_split_chunks_no_trailing_newline() {
        let data = b"line0\nline1";
        let chunks = split_into_chunks(data, 2);
        let total: u32 = chunks.iter().map(|c| c.line_count).sum();
        assert_eq!(total, 2);
        assert_eq!(chunks.last().unwrap().end_byte, data.len());
    }

    #[test]
    fn test_split_chunks_empty() {
        let data = b"";
        let chunks = split_into_chunks(data, 4);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].line_count, 0);
    }

    #[test]
    fn test_split_chunks_consistency() {
        // Verify chunks cover entire file without gaps or overlaps
        let data = b"aaa\nbbb\nccc\nddd\neee\nfff\nggg\nhhh\niii\njjj\n";
        for n in 1..=12 {
            let chunks = split_into_chunks(data, n);
            assert_eq!(chunks[0].start_byte, 0);
            assert_eq!(chunks.last().unwrap().end_byte, data.len());
            for w in chunks.windows(2) {
                assert_eq!(
                    w[0].end_byte,
                    w[1].start_byte,
                    "gap between chunks for n={}",
                    n
                );
            }
            let total: u32 = chunks.iter().map(|c| c.line_count).sum();
            assert_eq!(total, 10, "total lines wrong for n={}", n);
        }
    }

    #[test]
    fn test_parallel_matches_unified_simple() {
        // Small file should fall back to single-threaded
        let trace = "line1\nline2\nline3\n";
        let data = trace.as_bytes();
        let result = scan_unified_parallel(data, false, false, true, None, 2);
        assert!(result.is_ok());
    }
}
