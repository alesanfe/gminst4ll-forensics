import dnfile
dn = dnfile.dnPE("/home/vagrant/beket_extracted2/appy.exe")

# Listar todas las tablas disponibles
print("Tablas disponibles:", [t for t in dir(dn.net.mdtables) if not t.startswith('_')])

row = dn.net.mdtables.MethodDef.rows[0]
f = row.Flags
print("\nFlags corhdr_enum:", f.corhdr_enum)
print("Flags mdStatic:", f.mdStatic)
# Obtener valor numerico
import ctypes
print("Flags via struct:", row.struct.Flags)
