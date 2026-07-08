"""Unified module pipeline runner — registers all modules and runs them.

Entry point called from orchestrator.py after Stage 4/5 extraction.
"""

from pipeline.ingest.registry import ModuleRegistry, run_modules
from pipeline.ingest.modules import (
    FileTypeIdModule, ExtensionMismatchModule, HashFilterModule,
    DatParserModule, FlightReconstructionModule,
    ExifParserModule, GpxExportModule, PhotoFlightCrossrefModule,
    KeywordSearchModule, InterestingFilesModule, TimelineModule, CarvingModule,
    YaraScannerModule, TimelineCorrelationModule, CrossCaseRepoModule,
    TaggingModule, ReportingModule, CaseManagementModule,
)


def build_registry():
    """Build and return a fully populated ModuleRegistry."""
    reg = ModuleRegistry()
    # P1 — Standard
    reg.register(FileTypeIdModule())
    reg.register(ExtensionMismatchModule())
    reg.register(HashFilterModule())
    # D1-D2: DAT parsing + flight reconstruction
    reg.register(DatParserModule())
    reg.register(FlightReconstructionModule())
    # C5+D3+D4: EXIF, GPX, cross-ref
    reg.register(ExifParserModule())
    reg.register(GpxExportModule())
    reg.register(PhotoFlightCrossrefModule())
    # C6-C9: keyword search, interesting files, timeline, carving
    reg.register(KeywordSearchModule())
    reg.register(InterestingFilesModule())
    reg.register(TimelineModule())
    reg.register(CarvingModule())
    # P3: YARA, timeline correlation, cross-case repo
    reg.register(YaraScannerModule())
    reg.register(TimelineCorrelationModule())
    reg.register(CrossCaseRepoModule())
    # P4: tagging, reporting, case management
    reg.register(TaggingModule())
    reg.register(ReportingModule())
    reg.register(CaseManagementModule())
    return reg


def run_ingest_pipeline(case_id, file_rows, case_context=None, log_cb=None):
    """Convenience wrapper: build registry + run all modules."""
    registry = build_registry()
    return run_modules(registry, case_id, file_rows, case_context=case_context, log_cb=log_cb)
