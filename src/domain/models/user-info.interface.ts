// Contrato común que deben retornar todos los DAOs de autenticación.
// Mapea los campos necesarios para el JWT de audit.

export interface Sucursal {
  idSede:      string;
  descripcion: string;
}

export interface UserInfo {
  userId:           string;   // → JWT: sub
  username:         string;   // → JWT: username
  roles:            string[]; // → JWT: roles
  email:            string;
  // Datos de display — se incluyen en JWT para /auth/me sin DB lookup
  idUsuario?:       string;
  nombres?:         string;
  apellidoPaterno?: string;
  apellidoMaterno?: string;
  nombreCompleto?:  string;
  nombrePerfil?:    string;
  numeroDocumento?: string;
  sucursales?:      Sucursal[];
  // Token externo — claim privado, nunca expuesto al frontend
  macToken?:               string;
  perfil?:                 string;
  requirePasswordChange?:  boolean;
  // §9.6 — marca/tema del tenant. Autoritativo: sale de security.tenant_branding
  // (una fila por base HCE_SECURITY), NUNCA de una preferencia del cliente. Viaja
  // firmado como claim del JWT y se expone en GET auth/me.
  // ExternalAuthDao no lo puebla: MAC no tiene noción de marca, así que en un tenant
  // con MAC queda undefined y el frontend cae al tema por defecto.
  themeCode?:              string;
}
