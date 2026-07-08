const EXTRA_COLLAPSE_THRESHOLD = 8;

function _drvEscapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

function _drvRenderPills(identityEntries) {
  if (!identityEntries.length) return "";
  const pills = identityEntries
    .map(([, value]) => `<span class="drv-pill">${_drvEscapeHtml(value)}</span>`)
    .join("");
  return `<div class="drv-pills">${pills}</div>`;
}

function _drvRenderPhotoGrid(imageUrl, onAddPhoto) {
  const thumb = imageUrl
    ? `<div class="drv-photo-thumb" data-photo-path="${_drvEscapeHtml(imageUrl)}">
         <img src="${_drvEscapeHtml(imageUrl)}" alt="Reference photo" loading="lazy"
           onerror="this.outerHTML='<span class=\\'drv-no-image\\' style=\\'display:block;padding:8px;font-size:11px;color:var(--drv-text-muted);text-align:center;\\'>No image</span>'">
       </div>`
    : "";

  const addBtn = onAddPhoto
    ? `<div class="drv-photo-add" id="drv-add-photo-btn">
         <span>+ Add photo</span>
       </div>`
    : "";

  return `<div class="drv-photo-grid">${thumb}${addBtn}</div>`;
}

function _drvRenderAttrGrid(entries) {
  const cells = entries
    .map(([key, value]) => `
      <div class="drv-attr">
        <p class="drv-attr-label">${_drvEscapeHtml(formatDroneAttributeLabel(key))}</p>
        <p class="drv-attr-value">${_drvEscapeHtml(formatDroneAttributeValue(key, value))}</p>
      </div>`)
    .join("");
  return `<div class="drv-attr-grid">${cells}</div>`;
}

function _drvRenderGroup(name, entries) {
  return `
    <div class="drv-group">
      <div class="drv-group-header">
        <p class="drv-group-title">${_drvEscapeHtml(name)}</p>
      </div>
      ${_drvRenderAttrGrid(entries)}
    </div>`;
}

function _drvMeasureGroupHeight(card, width) {
  const probeHost = document.createElement("div");
  probeHost.style.position = "absolute";
  probeHost.style.visibility = "hidden";
  probeHost.style.pointerEvents = "none";
  probeHost.style.left = "0";
  probeHost.style.top = "0";
  probeHost.style.width = `${width}px`;
  probeHost.style.zIndex = "-1";

  const probe = card.cloneNode(true);
  probe.style.width = "100%";
  probeHost.appendChild(probe);
  document.body.appendChild(probeHost);
  const height = probe.getBoundingClientRect().height;
  probeHost.remove();
  return height;
}

function _drvPackGroups(container) {
  const grid = container.querySelector(".drv-groups-grid");
  if (!grid) return;

  const source = grid.querySelector(".drv-masonry-source");
  if (!source) return;

  const cards = Array.from(source.querySelectorAll(".drv-group"));
  const existingColumns = grid.querySelector(".drv-masonry-columns");
  if (existingColumns) existingColumns.remove();

  if (!cards.length) return;

  const gridWidth = grid.getBoundingClientRect().width;
  if (!gridWidth) return;

  const gap = 12;
  const columnCount = 2;
  const columnWidth = Math.max(0, Math.floor((gridWidth - gap) / columnCount));
  const columns = Array.from({ length: columnCount }, () => ({ height: 0, cards: [] }));

  cards.forEach(card => {
    const height = _drvMeasureGroupHeight(card, columnWidth);
    let targetIndex = 0;
    for (let i = 1; i < columns.length; i += 1) {
      if (columns[i].height < columns[targetIndex].height) targetIndex = i;
    }
    columns[targetIndex].cards.push(card.cloneNode(true));
    columns[targetIndex].height += height + gap;
  });

  const columnsWrap = document.createElement("div");
  columnsWrap.className = "drv-masonry-columns";
  columns.forEach(column => {
    const columnEl = document.createElement("div");
    columnEl.className = "drv-masonry-column";
    column.cards.forEach(card => columnEl.appendChild(card));
    columnsWrap.appendChild(columnEl);
  });

  grid.insertBefore(columnsWrap, source);
}

function _drvScheduleMasonry(container) {
  if (container._drvMasonryRaf) cancelAnimationFrame(container._drvMasonryRaf);
  container._drvMasonryRaf = requestAnimationFrame(() => {
    container._drvMasonryRaf = null;
    _drvPackGroups(container);
  });
}

function renderDroneRecord(container, row, options = {}) {
  if (!container || !row) {
    console.warn("renderDroneRecord: missing container or row");
    return;
  }

  if (container._drvMasonryObserver) {
    container._drvMasonryObserver.disconnect();
    container._drvMasonryObserver = null;
  }
  if (container._drvMasonryRaf) {
    cancelAnimationFrame(container._drvMasonryRaf);
    container._drvMasonryRaf = null;
  }

  const mergedAttributes = mergeDroneRecordAttributes(row);
  const { identity, groups, extra } = categorizeAttributes(mergedAttributes);

  const groupsHtml = groups.length
    ? `<div class="drv-groups-grid"><div class="drv-masonry-source" aria-hidden="true">${groups.map(g => _drvRenderGroup(g.name, g.entries)).join("")}</div></div>`
    : "";

  let extraHtml = "";
  if (extra.length > 0) {
    if (extra.length > EXTRA_COLLAPSE_THRESHOLD) {
      extraHtml = `
        <div id="drv-extra-block-${row.id}" style="display:none;">
          ${_drvRenderGroup("Additional attributes", extra)}
        </div>
        <button class="drv-toggle-extra" id="drv-toggle-extra-${row.id}">
          <span id="drv-toggle-label-${row.id}">Show ${extra.length} more attributes</span>
          <span class="drv-chevron">v</span>
        </button>`;
    } else {
      extraHtml = _drvRenderGroup("Additional attributes", extra);
    }
  }

  let imageUrl = mergedAttributes.image_url || mergedAttributes.image || '';
  if (!imageUrl && row.reference_image_path) {
    imageUrl = row.reference_image_path;
  }
  if (imageUrl) {
    imageUrl = imageUrl.replace(/\\/g, '/');
    imageUrl = imageUrl.replace(/^[a-zA-Z]:\//, '');
    if (!imageUrl.startsWith('http://') && !imageUrl.startsWith('https://') && !imageUrl.startsWith('/')) {
      imageUrl = '/' + imageUrl;
    }
  }

  const modelName = row.model_name || row.model || row.id;
  const companyName = row.company || row.manufacturer || "Unknown manufacturer";

  container.innerHTML = `
    <div class="drv-root">
      <div class="drv-header">
        <div class="drv-header-top">
          <div class="drv-header-left">
            <div class="drv-icon-badge">D</div>
            <div>
              <p class="drv-model">${_drvEscapeHtml(modelName)}</p>
              <p class="drv-manufacturer">${_drvEscapeHtml(companyName)}</p>
            </div>
          </div>
          <button class="drv-edit-btn" id="drv-edit-btn-${row.id}">Edit record</button>
        </div>
        ${_drvRenderPills(identity)}
      </div>

      ${_drvRenderPhotoGrid(imageUrl, options.onAddPhoto)}
      ${groupsHtml}
      ${extraHtml}
    </div>
  `;

  const editBtn = container.querySelector(`#drv-edit-btn-${row.id}`);
  if (editBtn && options.onEdit) {
    editBtn.addEventListener("click", () => options.onEdit(row));
  }

  const addPhotoBtn = container.querySelector("#drv-add-photo-btn");
  if (addPhotoBtn && options.onAddPhoto) {
    addPhotoBtn.addEventListener("click", () => options.onAddPhoto(row));
  }

  const toggleBtn = container.querySelector(`#drv-toggle-extra-${row.id}`);
  const extraBlock = container.querySelector(`#drv-extra-block-${row.id}`);
  if (toggleBtn && extraBlock) {
    let expanded = false;
    toggleBtn.addEventListener("click", () => {
      expanded = !expanded;
      extraBlock.style.display = expanded ? "block" : "none";
      toggleBtn.classList.toggle("expanded", expanded);
      container.querySelector(`#drv-toggle-label-${row.id}`).textContent =
        expanded ? "Hide additional attributes" : `Show ${extra.length} more attributes`;
    });
  }

  if (groups.length) {
    if (typeof ResizeObserver !== "undefined") {
      const grid = container.querySelector(".drv-groups-grid");
      if (grid) {
        let lastWidth = 0;
        container._drvMasonryObserver = new ResizeObserver(() => {
          const width = Math.round(grid.getBoundingClientRect().width);
          if (!width || width === lastWidth) return;
          lastWidth = width;
          _drvScheduleMasonry(container);
        });
        container._drvMasonryObserver.observe(grid);
      }
    }

    _drvScheduleMasonry(container);
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { renderDroneRecord };
}
