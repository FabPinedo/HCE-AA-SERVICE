import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Kafka, Producer, logLevel } from 'kafkajs';

export interface AuthAuditEntry {
  event_type:  string;   // LOGIN_SUCCESS | LOGIN_FAILED | TOKEN_REFRESH | LOGOUT
  level?:      string;
  trace_id?:   string;
  user_id?:    string;
  username?:   string;
  session_id?: string;
  action?:     string;
  outcome?:    string;
  reason?:     string;   // motivo de fallo (INVALID_CREDENTIALS, TIMEOUT, etc.)
  ip_address?: string;
  user_agent?: string;
}

@Injectable()
export class KafkaLoggerService implements OnModuleInit, OnModuleDestroy {
  private producer!: Producer;

  constructor(private readonly cfg: ConfigService) {}

  async onModuleInit() {
    const kafka = new Kafka({
      clientId: 'auth-pruebas-auth-logger',
      brokers:  (this.cfg.get<string>('KAFKA_BROKER', 'localhost:9092')).split(','),
      logLevel: logLevel.ERROR,
    });
    this.producer = kafka.producer();
    await this.producer.connect();
  }

  async onModuleDestroy() {
    await this.producer.disconnect();
  }

  async log(entry: AuthAuditEntry): Promise<void> {
    try {
      await this.producer.send({
        topic: this.cfg.get<string>('KAFKA_TOPIC', 'platform.logs'),
        messages: [{
          value: JSON.stringify({
            source_system: 'auth-pruebas-auth',
            timestamp:     new Date().toISOString(),
            ...entry,
            level: entry.level ?? 'INFO',
          }),
        }],
      });
    } catch {
      // Fire and forget — nunca interrumpe el flujo de autenticación
    }
  }
}
