const el = (id) => document.getElementById(id);
const localText = (en, ar) =>
  document.documentElement.lang === "ar" ? ar : en;
let controller,
  report,
  busy = false,
  statusText = ["", ""];
function status(en, ar) {
  statusText = [en, ar];
  el("status").textContent = localText(en, ar);
}
function node(tag, text) {
  const element = document.createElement(tag);
  element.textContent = text;
  return element;
}
function rows(id, data, tag = "p") {
  el(id).replaceChildren(...data.map((value) => node(tag, value)));
}
function entropy(samples) {
  const canvas = el("entropy"),
    ctx = canvas.getContext("2d");
  const w = canvas.width,
    h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.font = "13px sans-serif";
  for (const level of [0, 4, 8]) {
    const y = h - 14 - (level / 8) * (h - 28);
    ctx.fillStyle = "#a6c5ba";
    ctx.fillText(level, 8, y + 4);
    ctx.fillStyle = "#335453";
    ctx.fillRect(28, y, w - 40, 1);
  }
  ctx.fillStyle = "#84dbb4";
  const width = (w - 40) / Math.max(samples.length, 1);
  samples.forEach((s, i) => {
    const height = ((h - 28) * s.entropy) / 8;
    ctx.fillRect(
      28 + i * width,
      h - 14 - height,
      Math.max(width - 1, 1),
      Math.max(height, 1),
    );
  });
  el("coverage").textContent =
    localText(
      "Samples across the image · bits per byte",
      "عينات موزعة على الصورة · بت لكل بايت",
    ) +
    " · " +
    samples.length;
}
function filterMarkers() {
  const query = el("markerFilter").value.toLowerCase().trim();
  const matches = report.analysis.signatures;
  const visible = matches.filter(s =>
    [s.name, s.magic_hex, s.description, String(s.offset), "0x"+s.offset.toString(16)]
      .some(value => value.toLowerCase().includes(query)));
  el("matchCount").textContent = visible.length + " / " + matches.length;
  el("signatures").replaceChildren(
    ...visible.map((s) => {
      const tr = node("tr", "");
      tr.append(
        ...[
          s.name,
          "0x" + s.offset.toString(16),
          s.magic_hex,
          s.description,
        ].map((v) => node("td", v)),
      );
      return tr;
    }),
  );
 }
el("markerFilter").oninput = filterMarkers;
function render() {
  const { input, analysis: a } = report;
  el("results").hidden = false;
  el("reportName").textContent = input.name;
  const metrics = [
    [
      localText("Image size", "حجم الصورة"),
      (input.size_bytes / 1048576).toFixed(2) + " MiB",
    ],
    [localText("Signature hits", "التواقيع"), a.signatures.length],
    [
      localText("Indicator rules", "قواعد المؤشرات"),
      a.heuristic_findings.length,
    ],
    [
      localText("Printable strings", "السلاسل النصية"),
      a.printable_strings_count,
    ],
  ];
  el("metrics").replaceChildren(
    ...metrics.map(([label, value]) => {
      const cell = node("div", "");
      cell.className = "metric";
      cell.append(node("span", label), node("strong", value));
      return cell;
    }),
  );
  entropy(a.entropy_samples);
  el("signatureNote").textContent =
    a.signatures.length >= 200
      ? localText(
          "Display limit reached (200 hits). Additional markers may exist.",
          "تم بلوغ الحد (200 توقيع). قد توجد تواقيع أخرى.",
        )
      : localText(
          "Byte patterns and their offsets in the input image.",
          "أنماط البايتات وإزاحاتها في ملف الإدخال.",
        );
  filterMarkers();
  if (!a.signatures.length)
    el("signatureNote").textContent = localText(
      "No known markers found.",
      "لم تُكتشف تواقيع معروفة.",
    );
  el("findings").replaceChildren(
    ...a.heuristic_findings.map((f) => {
      const item = node("article", "");
      item.append(
        node("strong", f.rule),
        node("p", localText("Confidence", "الثقة") + " · " + f.confidence),
        node("p", f.message),
        ...f.evidence.map((e) => node("pre", e)),
      );
      return item;
    }),
  );
  if (!a.heuristic_findings.length)
    rows("findings", [
      localText("No heuristic findings.", "لم تُسجّل مؤشرات استدلالية."),
    ]);
  el("kernels").textContent =
    a.kernel_versions.join(", ") ||
    localText(
      "No version string detected.",
      "لم يُكتشف نص يدل على إصدار النواة.",
    );
  rows(
    "cves",
    a.cve_matches.length
      ? a.cve_matches.map((c) => JSON.stringify(c, null, 2))
      : [
          localText(
            "No CVE feed was supplied for this scan.",
            "لم تُزوّد قاعدة CVE لهذا الفحص.",
          ),
        ],
  );
  el("metadata").replaceChildren(
    ...[
      ["SHA-256", input.sha256],
      [localText("Size in bytes", "الحجم بالبايت"), input.size_bytes],
      [localText("Analyzer", "المحلل"), report.tool + " " + report.version],
    ].flatMap(([k, v]) => [node("dt", k), node("dd", v)]),
  );
  if (a.container_header) {
    el("metadata").append(
      node("dt", localText("Container header", "ترويسة الحاوية")),
      node("dd", a.container_header.format + " · " + a.container_header.validated)
    );
  }
  rows("limits", report.limitations, "li");
  const archive = report.archive_inspection;
  el("archiveSection").hidden = !archive;
  if (archive) {
    const area = el("archiveFiles");
    area.replaceChildren();
    if (archive.status === "completed") {
      const tree = node("ul", ""),
        dirs = new Map([["", tree]]);
      for (const entry of archive.entries) {
        let parent = "",
          list = tree;
        for (const part of entry.path.split("/")) {
          const path = parent ? parent + "/" + part : part;
          if (!dirs.has(path)) {
            const li = node("li", part);
            list.append(li);
            if (path !== entry.path || entry.status === "directory") {
              const sub = node("ul", "");
              li.append(sub);
              dirs.set(path, sub);
            } else li.append(node("small", " · " + entry.size_bytes + " B"));
          }
          parent = path;
          list = dirs.get(path);
        }
      }
      area.append(tree);
    } else area.append(node("p", archive.reason));
  }
}
function applyLanguage(lang) {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-ar]").forEach((e) => {
    e.dataset.en ??= e.textContent;
    e.textContent = localText(e.dataset.en, e.dataset.ar);
  });
  el("languageToggle").textContent = localText("العربية", "English");
  if (el("file").files[0])
    el("fileName").textContent = el("file").files[0].name;
  status(...statusText);
  if (report) render();
}
el("languageToggle").onclick = () => applyLanguage(localText("ar", "en"));
function selectFile() {
  report = null;
  el("results").hidden = true;
  status("", "");
  const file = el("file").files[0];
  el("fileName").textContent =
    file?.name || localText("No file selected", "لم يتم اختيار ملف");
  el("scan").disabled = !file || file.size > 128 * 1048576;
  if (file?.size > 128 * 1048576)
    status(
      "Choose an image of 128 MiB or less.",
      "اختر ملفاً بحجم 128 MiB أو أقل.",
    );
}
el("file").onchange = selectFile;
el("scanForm").ondragover = (e) => e.preventDefault();
el("scanForm").ondrop = (e) => {
  e.preventDefault();
  if (busy || !e.dataTransfer.files.length) return;
  el("file").files = e.dataTransfer.files;
  selectFile();
};
el("scanForm").onsubmit = async (e) => {
  e.preventDefault();
  if (busy || el("scan").disabled) return;
  busy = true;
  el("example").disabled = true;
  el("scan").disabled = el("file").disabled = true;
  controller = new AbortController();
  el("cancel").hidden = false;
  el("inspectArchive").disabled = true;
  status("Analyzing locally…", "جارٍ التحليل محلياً…");
  try {
    const fd = new FormData();
    fd.append("upload", el("file").files[0]);
    fd.append("inspect_archive", el("inspectArchive").checked);
    const response = await fetch("/scan", {
      method: "POST",
      body: fd,
      signal: controller.signal,
    });
    const data = await response.json();
    if (!response.ok) throw Error(data.detail || response.status);
    el("markerFilter").value = "";
    report = data;
    render();
    status("Analysis complete.", "اكتمل التحليل.");
    el("results").scrollIntoView({ block: "start" });
  } catch (error) {
    if (error.name === "AbortError")
      status("Analysis cancelled.", "أُلغي التحليل.");
    else
      status(
        "Scan failed · " + error.message,
        "تعذّر الفحص · " + error.message,
      );
  } finally {
    busy = false;
    el("example").disabled = false;
    el("cancel").hidden = true;
    el("inspectArchive").disabled = false;
    el("file").disabled = el("scan").disabled = false;
  }
};
el("example").onclick = async () => {
  if (busy) return;
  busy = true;
  el("example").disabled = el("file").disabled = el("scan").disabled = true;
  try {
    const response = await fetch("/assets/example-report.json");
    if (!response.ok) throw Error(response.status);
    report = await response.json();
    el("markerFilter").value = "";
    render();
    status("Showing the bundled synthetic sample.", "هذا تقرير العينة التجريبية المرفقة.");
    el("results").scrollIntoView({block: "start"});
  } catch (error) {
    status("Sample report unavailable.", "تعذّر فتح تقرير العينة.");
  } finally {
    busy = false;
    el("example").disabled = el("file").disabled = false;
    const file = el("file").files[0];
    el("scan").disabled = !file || file.size > 128*1048576;
  }
};
el("cancel").onclick = () => controller?.abort();
el("download").onclick = () => {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = report.input.name + ".fsa.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
el("print").onclick = () => window.print();
applyLanguage("en");
