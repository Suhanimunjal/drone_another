const CATEGORY_RULES = [
  {
    name: "Flight performance",
    keys: ["battery life", "flight time", "max altitude", "max range",
           "max speed", "endurance", "climb rate", "descent rate", "hover accuracy"],
  },
  {
    name: "Physical specs",
    keys: ["payload", "weight", "dim.", "dimension", "max storage",
           "wind resist", "material", "ip rating", "frame"],
  },
  {
    name: "Camera and imaging",
    keys: ["camera", "gimbal", "video", "sensor", "zoom", "bitrate", "fpv"],
  },
  {
    name: "Connectivity and navigation",
    keys: ["gps", "transmission", "obstacle", "app compat", "ocusync",
           "glonass", "galileo", "beidou", "satellite", "signal"],
  },
  {
    name: "Power and charging",
    keys: ["battery type", "charging"],
  },
  {
    name: "Commercial info",
    keys: ["price", "warranty", "rating", "review", "units", "stock",
           "sold", "release year", "color", "status", "controller"],
  },
];

const IDENTITY_FIELDS = ["type", "category", "airframe_class", "airframe class"];

const NON_ATTRIBUTE_FIELDS = ["id", "model_name", "company", "reference_image_path", "extra_attributes", "model", "manufacturer", "aliases"];

const LABEL_OVERRIDES = {
  gps: "GPS",
  gps_systems: "GPS Systems",
  camera_resolution: "Camera Resolution",
  camera_sensor: "Camera Sensor",
  gimbal_axes: "Gimbal Axes",
  video_bitrate: "Video Bitrate",
  obstacle_sensors: "Obstacle Sensors",
  obstacle_avoidance: "Obstacle Avoidance",
  transmission_range: "Transmission Range",
  transmission_system: "Transmission System",
  app_compatibility: "App Compatibility",
  controller_included: "Controller Included",
  charging_time: "Charging Time",
  max_wind_resist: "Max Wind Resist.",
  dim_folded: "Dim. Folded",
  dim_unfolded: "Dim. Unfolded",
  release_year: "Release Year",
  country_of_origin: "Country of Origin",
  battery_life: "Battery Life",
  max_altitude: "Max Altitude",
  max_range: "Max Range",
  max_speed: "Max Speed",
  max_storage: "Max Storage",
  wind_resistance: "Wind Resistance",
  battery_type: "Battery Type",
  battery_cap: "Battery Cap.",
  avg_rating: "Avg Rating",
  review_count: "Review Count",
  units_in_stock: "Units In Stock",
  units_sold: "Units Sold",
  color_options: "Color Options",
  ip_rating: "IP Rating",
  operating_temp: "Operating Temp",
  material: "Material",
  payload: "Payload",
  weight: "Weight",
  endurance: "Endurance",
  flight_time: "Flight Time",
};

const UNIT_SUFFIX = {
  endurance: " min",
  endurance_min: " min",
  battery_life: " min",
  charging_time: " min",
  payload: " g",
  payload_kg: " kg",
  weight: " g",
  weight_kg: " kg",
  video_bitrate: " Mbps",
  transmission_range: " km",
  range_km: " km",
  max_range: " km",
  max_speed: " km/h",
  speed: " km/h",
  max_altitude: " m",
  ceiling: " m",
  gimbal_axes: "-axis",
  max_storage: " GB",
  storage_capacity: " GB",
  battery_cap: " mAh",
  capacity: " mAh",
  max_wind_resist: " m/s",
  wind_resistance: " m/s",
  width: " mm",
  length: " mm",
  height: " mm",
  dim_folded: " mm",
  dim_unfolded: " mm",
  wingspan_m: " m",
  photo_res: " MP",
  price: " $",
  cost: " $",
  msrp: " $",
};

function normalizeDroneAttributeKey(key) {
  return String(key || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function formatDroneAttributeLabel(key) {
  const normalized = normalizeDroneAttributeKey(key);
  if (LABEL_OVERRIDES[normalized]) return LABEL_OVERRIDES[normalized];
  return normalized
    .replace(/_/g, " ")
    .replace(/\b\w/g, c => c.toUpperCase());
}

function formatDroneAttributeValue(key, value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);

  const normalized = normalizeDroneAttributeKey(key);
  const suffix = UNIT_SUFFIX[normalized] || "";
  return `${value}${suffix}`;
}

function normalizeCategoryText(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ");
}

function mergeDroneRecordAttributes(row) {
  const merged = {};
  const seen = new Set();

  Object.entries(row || {}).forEach(([key, value]) => {
    if (NON_ATTRIBUTE_FIELDS.includes(key) || NON_ATTRIBUTE_FIELDS.includes(normalizeDroneAttributeKey(key))) return;
    if (value === null || value === undefined || value === "") return;
    const normalized = normalizeDroneAttributeKey(key);
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    merged[normalized] = value;
  });

  let extra = row?.extra_attributes;
  if (typeof extra === "string") {
    try { extra = JSON.parse(extra); } catch (e) { extra = {}; }
  }
  Object.entries(extra || {}).forEach(([key, value]) => {
    if (value === null || value === undefined || value === "") return;
    const normalized = normalizeDroneAttributeKey(key);
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    merged[normalized] = value;
  });

  return merged;
}

function categorizeAttributes(attributes) {
  const identity = [];
  const groups = CATEGORY_RULES.map(r => ({ ...r, entries: [] }));
  const extra = [];

  Object.entries(attributes || {}).forEach(([key, value]) => {
    const lower = normalizeCategoryText(key);

    if (IDENTITY_FIELDS.some(k => lower === normalizeCategoryText(k))) {
      identity.push([key, value]);
      return;
    }

    const match = groups.find(g => g.keys.some(k => lower.includes(normalizeCategoryText(k))));
    if (match) {
      match.entries.push([key, value]);
    } else {
      extra.push([key, value]);
    }
  });

  return {
    identity,
    groups: groups.filter(g => g.entries.length > 0),
    extra,
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    categorizeAttributes,
    mergeDroneRecordAttributes,
    CATEGORY_RULES,
    normalizeDroneAttributeKey,
    formatDroneAttributeLabel,
    formatDroneAttributeValue,
  };
}
