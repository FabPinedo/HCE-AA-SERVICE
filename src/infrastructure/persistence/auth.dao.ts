import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { UserInfo } from '../../domain/models/user-info.interface';

// Autenticación local contra variables de entorno — STUB de desarrollo.
//
// NO es la implementación local real: esa es LocalSecurityAuthDao
// (local-security-auth.dao.ts), respaldada por HCE_SECURITY vía ms-bs-core-security
// y activa con AUTH_MODE=local. Esta clase se conserva únicamente como atajo para
// levantar el servicio sin base de datos ni gateway; no está registrada en
// app.module.ts y no implementa IMacAuthDao.
@Injectable()
export class AuthDao {
  constructor(private readonly config: ConfigService) {}

  async validateUser(username: string, password: string): Promise<UserInfo | null> {
    const validUser = this.config.get<string>('AUTH_USER',     'admin');
    const validPass = this.config.get<string>('AUTH_PASSWORD', '');
    if (username !== validUser || password !== validPass) return null;
    return {
      userId:   `local-${username}`,
      username,
      roles:    ['admin'],
      email:    '',
    };
  }
}
