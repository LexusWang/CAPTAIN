ExtensionNameType = [
    'pdf',
    'doc',
    'docx',
    'xml',
    'xlsx',
    'cpp'
]

extentsion_name_type = {}
for i, item in enumerate(ExtensionNameType):
    extentsion_name_type[item] = i

DirNameType = set([
    'usr','sys','run','sbin','etc',
    'var','home','maildrop','stat',
    'active','incoming','tmp','media',
    'root','data','dev','proc','lib64','lib','bin'
])

dir_name_type = {}

for i, item in enumerate(list(DirNameType)):
    dir_name_type[item] = i