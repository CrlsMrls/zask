// Package audit provides structured logging and observability for ZASK.
//
// All kernel decisions and AI justifications are streamed to a structured
// NDJSON audit log, which integrates with Fluent Bit for real-time shipping
// to SIEM or centralized storage.
package audit
