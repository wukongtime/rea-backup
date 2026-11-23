import { z } from "zod";
import { evidenceSubjectTarget } from "../evidence.js";
import { err, ok } from "../result.js";
import {
  ffsTypeNameSchema,
  guidSchema,
  uefiResultSchemas,
  uefiSectionTypeNameSchema,
  type UefiFfsFileRecord,
  type UefiInspectResult,
} from "../uefi/uefiFirmwareAnalysis.js";
import { analysisViewInputError } from "./analysisViewErrors.js";
import {
  boundedViewMessages,
  completeWithinViewCoverage,
  pageViewCoverage,
} from "./analysisViewCoverage.js";
import {
  createAnalysisViewResultReader,
  parentArtifactPath,
  validateAnalysisViewSubject,
  type AnalysisViewParent,
} from "./analysisViewParent.js";
import {
  assertOwnedView,
  type AdmittedView,
  type SummaryAnalysisView,
} from "./analysisViewShape.js";

const inspection = uefiResultSchemas.inspect_uefi_firmware;
const volumeRecord = inspection.shape.firmware_volumes.element;
const fileRecord = volumeRecord.shape.ffs_files.element;
const sectionRecord = fileRecord.shape.sections.element;
const count = z.int().nonnegative();
const sourceIndex = {
  source_index: count.describe(
    "Index in the parent's flattened collection order",
  ),
};
const page = {
  offset: z.int().nonnegative().default(0),
  limit: z.int().positive().max(256).default(32),
};
const exactNames = <Schema extends z.ZodType>(schema: Schema, what: string) =>
  z
    .array(schema)
    .min(1)
    .max(64)
    .optional()
    .describe(`Exact ${what}; any listed value matches`);

const pagedCollection = <Name extends string>(collection: Name) =>
  z.strictObject({
    kind: z.literal("uefi-firmware"),
    collection: z.literal(collection),
    ...page,
  });

/** Retained firmware facts selected by collection, exact filters and stable pages. */
export const uefiFirmwareViewRequestSchema = z.discriminatedUnion(
  "collection",
  [
    pagedCollection("volumes"),
    z.strictObject({
      kind: z.literal("uefi-firmware"),
      collection: z.literal("files"),
      guids: exactNames(guidSchema, "lowercase FFS file GUIDs"),
      ui_names: exactNames(z.string().min(1), "user-interface names"),
      type_names: exactNames(ffsTypeNameSchema, "FFS file type names"),
      volume_path: z
        .string()
        .min(1)
        .optional()
        .describe("Exact logical_path of the owning firmware volume"),
      offset: page.offset,
      limit: z
        .int()
        .positive()
        .max(256)
        .default(16)
        .describe("File rows carry their section lists"),
    }),
    z.strictObject({
      kind: z.literal("uefi-firmware"),
      collection: z.literal("sections"),
      file_path: z
        .string()
        .min(1)
        .optional()
        .describe("Exact logical_path of the owning FFS file"),
      type_names: exactNames(uefiSectionTypeNameSchema, "section type names"),
      ...page,
    }),
    pagedCollection("unknown-regions"),
    pagedCollection("integrity"),
    pagedCollection("psp-tables"),
    pagedCollection("psp-candidates"),
  ],
);
type UefiFirmwareView = z.output<typeof uefiFirmwareViewRequestSchema>;

/** Enough of each section to size, verify and extract it without a sections page. */
const fileSectionSchema = sectionRecord.pick({
  type_name: true,
  offset: true,
  header_length: true,
  length: true,
  sha256: true,
  source_stream: true,
});
const fileRow = fileRecord.omit({ sections: true }).extend({
  volume_logical_path: z.string(),
  sections: z
    .array(fileSectionSchema)
    .describe(
      "The file's sections in order; the sections collection carries complete records",
    ),
  ...sourceIndex,
});
const sectionRow = sectionRecord.extend({
  file_logical_path: z.string(),
  ...sourceIndex,
});
export const uefiFirmwareViewItemsSchema = z.union([
  z.array(
    volumeRecord
      .omit({ ffs_files: true })
      .extend({ file_count: count, ...sourceIndex }),
  ),
  z.array(fileRow),
  z.array(sectionRow),
  z.array(inspection.shape.unknown_regions.element.extend(sourceIndex)),
  z.array(inspection.shape.integrity.element.extend(sourceIndex)),
  z.array(inspection.shape.psp_tables.element.extend(sourceIndex)),
  z.array(inspection.shape.psp_candidates.element.extend(sourceIndex)),
]);

const tally = <Name extends z.ZodType>(name: Name) =>
  z.array(z.strictObject({ name, count }));
/** Fixed-size counts shared by summaries and pages; rows stay in pages. */
export const uefiFirmwarePageContextSchema = inspection
  .pick({ parser: true, input_size: true, flash_image: true, coverage: true })
  .extend({
    volume_count: count,
    top_level_volume_count: count.describe("Volumes at depth 0"),
    file_count: count,
    named_file_count: count.describe("FFS files with a ui_string"),
    section_count: count,
    unknown_region_count: count,
    integrity_count: count,
    psp_table_count: count,
    psp_candidate_count: count,
  });
export const uefiFirmwareSummarySchema = uefiFirmwarePageContextSchema.extend({
  file_types: tally(ffsTypeNameSchema),
  section_types: tally(uefiSectionTypeNameSchema),
  volume_depths: z.array(z.strictObject({ depth: count, count })),
});

const readReport = createAnalysisViewResultReader(inspection);

const tallied = <Name>(names: Iterable<Name>) => {
  const counts = new Map<Name, number>();
  for (const name of names) counts.set(name, (counts.get(name) ?? 0) + 1);
  return [...counts].map(([name, n]) => ({ name, count: n }));
};

interface FileEntry {
  readonly volume: string;
  readonly file: UefiFfsFileRecord;
}

/** Files in volume order, each with its owning volume path. */
const flattenedFiles = (report: UefiInspectResult): FileEntry[] =>
  report.firmware_volumes.flatMap((volume) =>
    volume.ffs_files.map((file) => ({ volume: volume.logical_path, file })),
  );

const pageContext = (r: UefiInspectResult, files: readonly FileEntry[]) => ({
  parser: r.parser,
  input_size: r.input_size,
  flash_image: r.flash_image,
  coverage: r.coverage,
  volume_count: r.firmware_volumes.length,
  top_level_volume_count: r.firmware_volumes.filter((v) => v.depth === 0)
    .length,
  file_count: files.length,
  named_file_count: files.filter(({ file }) => file.ui_string !== null).length,
  section_count: files.reduce((n, { file }) => n + file.sections.length, 0),
  unknown_region_count: r.unknown_regions.length,
  integrity_count: r.integrity.length,
  psp_table_count: r.psp_tables.length,
  psp_candidate_count: r.psp_candidates.length,
});

const firmwareSummary = (
  r: UefiInspectResult,
  files: readonly FileEntry[],
) => ({
  ...pageContext(r, files),
  file_types: tallied(files.map(({ file }) => file.type_name)),
  section_types: tallied(
    files.flatMap(({ file }) => file.sections.map((s) => s.type_name)),
  ),
  volume_depths: tallied(r.firmware_volumes.map((v) => v.depth))
    .sort((a, b) => a.name - b.name)
    .map(({ name, count: n }) => ({ depth: name, count: n })),
});

const fileMatches = (
  view: Extract<UefiFirmwareView, { collection: "files" }>,
  { volume, file }: FileEntry,
): boolean =>
  (view.guids === undefined || view.guids.includes(file.guid)) &&
  (view.ui_names === undefined ||
    (file.ui_string !== null && view.ui_names.includes(file.ui_string))) &&
  (view.type_names === undefined || view.type_names.includes(file.type_name)) &&
  (view.volume_path === undefined || view.volume_path === volume);

/**
 * Match rows with their original indices, then project only the selected page.
 * The total counts every matching row.
 */
const pageOf = <Row, Item>(
  view: { readonly offset: number; readonly limit: number },
  rows: readonly Row[],
  matches: (row: Row) => boolean,
  project: (row: Row, sourceIndex: number) => Item,
) => {
  const matched: { row: Row; index: number }[] = [];
  rows.forEach((row, index) => {
    if (matches(row)) matched.push({ row, index });
  });
  return {
    total: matched.length,
    rows: matched
      .slice(view.offset, view.offset + view.limit)
      .map(({ row, index }) => project(row, index)),
  };
};
const all = (): boolean => true;
const indexedRow = <Row extends object>(row: Row, source_index: number) => ({
  ...row,
  source_index,
});

const selectedRows = (
  view: UefiFirmwareView,
  r: UefiInspectResult,
  files: readonly FileEntry[],
) => {
  switch (view.collection) {
    case "volumes":
      return pageOf(view, r.firmware_volumes, all, (volume, index) => {
        const { ffs_files, ...rest } = volume;
        return { ...rest, file_count: ffs_files.length, source_index: index };
      });
    case "files":
      return pageOf(
        view,
        files,
        (entry) => fileMatches(view, entry),
        ({ volume, file }, index) => {
          const { sections, ...rest } = file;
          return {
            ...rest,
            volume_logical_path: volume,
            sections: sections.map((section) => ({
              type_name: section.type_name,
              offset: section.offset,
              header_length: section.header_length,
              length: section.length,
              sha256: section.sha256,
              source_stream: section.source_stream,
            })),
            source_index: index,
          };
        },
      );
    case "sections":
      return pageOf(
        view,
        files.flatMap(({ file }) =>
          file.sections.map((section) => ({
            file: file.logical_path,
            section,
          })),
        ),
        (row) =>
          (view.file_path === undefined || view.file_path === row.file) &&
          (view.type_names === undefined ||
            view.type_names.includes(row.section.type_name)),
        (row, index) => ({
          ...row.section,
          file_logical_path: row.file,
          source_index: index,
        }),
      );
    case "unknown-regions":
      return pageOf(view, r.unknown_regions, all, indexedRow);
    case "integrity":
      return pageOf(view, r.integrity, all, indexedRow);
    case "psp-tables":
      return pageOf(view, r.psp_tables, all, indexedRow);
    case "psp-candidates":
      return pageOf(view, r.psp_candidates, all, indexedRow);
  }
};

/** Page retained UEFI cartography without rerunning the parser or reopening the image. */
export const projectUefiFirmwareView = (
  parent: AnalysisViewParent,
  view: AdmittedView,
) => {
  if (view.kind !== "summary" && view.kind !== "uefi-firmware")
    return err(
      analysisViewInputError([
        {
          path: ["view"],
          reason: "invalid_value",
          message:
            "UEFI firmware Evidence supports summary and uefi-firmware views.",
        },
      ]),
    );
  assertOwnedView<SummaryAnalysisView | UefiFirmwareView>(
    view,
    "summary",
    "uefi-firmware",
  );
  const parsed = readReport(parent);
  if (!parsed.ok) return parsed;
  const r = parsed.value;
  const bound = validateAnalysisViewSubject(
    parent.subject,
    r.flash_image.sha256,
  );
  if (!bound.ok) return bound;
  const files = flattenedFiles(r);
  const shared = {
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_uefi_firmware" as const,
    parent_digest: parent.evidenceId.slice(3),
    artifact: {
      path:
        evidenceSubjectTarget(parent.subject)?.path ??
        parentArtifactPath(parent),
      sha256: r.flash_image.sha256,
    },
    limitations: boundedViewMessages(
      [...parent.limitations, ...r.limitations],
      parent.evidenceId,
      "limitations",
    ),
    unknowns: [
      "Page exhaustion covers retained rows only; volumes, files and sections beyond the parser's depth, volume or file limits remain unmapped.",
    ],
  };
  if (view.kind === "summary")
    return ok({
      ...shared,
      kind: "summary" as const,
      view,
      summary: firmwareSummary(r, files),
      coverage: completeWithinViewCoverage(r.firmware_volumes.length),
    });
  const { rows, total } = selectedRows(view, r, files);
  return ok({
    ...shared,
    kind: "uefi-firmware" as const,
    view,
    uefi_firmware: pageContext(r, files),
    items: rows,
    coverage: pageViewCoverage(view.offset, rows.length, total),
  });
};
