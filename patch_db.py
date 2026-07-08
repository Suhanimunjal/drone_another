import sqlite3, os

conn = sqlite3.connect('forensics.db')

raw1 = r'D:\new_WEBSITE\uploads\disk_images\be936896-4aa6-4d33-9e23-40acf06f8658\converted.raw'
if os.path.isfile(raw1):
    conn.execute(
        "UPDATE DiskImages SET filepath=?, format='raw', status='pending', error_message=NULL WHERE id=1",
        (raw1,)
    )
    print('Image 1 updated -> ', raw1, '  size:', os.path.getsize(raw1), 'bytes')
else:
    print('ERROR: raw1 not found:', raw1)

conn.commit()
conn.close()
print('Done.')
