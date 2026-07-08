import sqlite3, json, zipfile, os, xml.etree.ElementTree as ET

xlsx = 'database/Drone_Database.xlsx'
img_out_dir = 'static/drone_images'
os.makedirs(img_out_dir, exist_ok=True)

# Extract images from xlsx
with zipfile.ZipFile(xlsx) as z:
    drawing_xml = z.read('xl/drawings/drawing1.xml').decode('utf-8')
    rels_xml = z.read('xl/drawings/_rels/drawing1.xml.rels').decode('utf-8')
    # Extract image files
    for name in z.namelist():
        if 'media' in name and name.endswith('.png'):
            fname = os.path.basename(name)
            with z.open(name) as src, open(os.path.join(img_out_dir, fname), 'wb') as dst:
                dst.write(src.read())
            print('Extracted:', fname)

# Parse rels to get rId -> image filename
rels_root = ET.fromstring(rels_xml)
rid_to_img = {}
for rel in rels_root:
    rid = rel.get('Id')
    target = rel.get('Target', '')
    if 'media' in target:
        rid_to_img[rid] = os.path.basename(target)
print('rId map:', rid_to_img)

# Parse drawing XML to get sheet row -> rId
ns = {
    'xdr': 'http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing',
    'a':   'http://schemas.openxmlformats.org/drawingml/2006/main',
    'r':   'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
}
draw_root = ET.fromstring(drawing_xml)
row_to_img = {}
for anchor in draw_root.findall('xdr:twoCellAnchor', ns):
    frm = anchor.find('xdr:from', ns)
    row_el = frm.find('xdr:row', ns) if frm is not None else None
    pic = anchor.find('xdr:pic', ns)
    blip = pic.find('.//a:blip', ns) if pic is not None else None
    if row_el is not None and blip is not None:
        r_key = '{http://schemas.openxmlformats.org/officeDocument/2006/relationships}embed'
        rid = blip.get(r_key)
        row_num = int(row_el.text)
        img_file = rid_to_img.get(rid, '')
        row_to_img[row_num] = img_file
        print(f'Sheet row {row_num} -> {img_file}')

print('Row->image map:', row_to_img)

# Update SQLite records
conn = sqlite3.connect('forensics.db')
conn.row_factory = sqlite3.Row
rows = conn.execute('SELECT id, model_name, extra_attributes FROM DroneRegistry ORDER BY id').fetchall()
updated = 0
for idx, r in enumerate(rows):
    extra = json.loads(r['extra_attributes']) if r['extra_attributes'] else {}
    # Data rows start at sheet row 1 (row 0 is header)
    img_file = row_to_img.get(idx + 1, '')
    if img_file:
        img_url = '/static/drone_images/' + img_file
        extra['image_url'] = img_url
        extra['image'] = img_url
        conn.execute('UPDATE DroneRegistry SET extra_attributes=? WHERE id=?',
                     (json.dumps(extra), r['id']))
        updated += 1
        print(f'Updated {r["model_name"]} -> {img_url}')
    else:
        print(f'No image for {r["model_name"]} (idx {idx})')

conn.commit()
conn.close()
print(f'Done. Updated {updated} drones.')
