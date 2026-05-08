from __future__ import annotations
from typing import List, Dict


HARDENING_DB: Dict[str, List[str]] = {
    "T1190": [
        "Reforzar validación de entrada y límites de tamaño en todos los endpoints.",
        "Agregar pruebas regresivas para entradas límite y fuzzing en CI.",
        "Asegurar compilación con -fstack-protector-strong, RELRO, PIE.",
        "Aplicar WAF con reglas para payloads anómalos.",
        "Actualizar dependencias con CVEs conocidos (SCA automatizado).",
    ],
    "T1059": [
        "Reemplazar shell=True con listas de argumentos explícitas.",
        "Implementar allowlist de comandos autorizados por proceso.",
        "Habilitar script block logging para todos los intérpretes.",
        "Auditar automatizaciones con trazabilidad completa por identidad.",
    ],
    "T1053": [
        "Auditar y eliminar tareas programadas no autorizadas.",
        "Monitorear cambios en crontab y at-jobs vía FIM.",
        "Restringir permisos de escritura en cron a usuarios autorizados.",
    ],
    "T1078": [
        "Forzar MFA en todas las cuentas interactivas y de servicio.",
        "Rotar credenciales comprometidas inmediatamente.",
        "Implementar detección de anomalías de credenciales (UEBA).",
    ],
    "T1548": [
        "Revisar reglas sudo y eliminar concesiones NOPASSWD amplias.",
        "Habilitar logging PAM para eventos de elevación.",
        "Implementar modelo de acceso privilegiado just-in-time.",
    ],
    "T1562": [
        "Implementar monitoreo de salud de agentes con alertas.",
        "Forzar logging inmutable/append-only en almacenamiento separado.",
        "Alertar por ausencia de telemetría esperada (gap detection).",
    ],
    "T1003": [
        "Habilitar Credential Guard / LSA Protection.",
        "Restringir lectura de memoria LSASS vía política EDR.",
        "Rotar todos los secretos expuestos tras un evento de credential access.",
    ],
    "T1082": [
        "Desplegar canary tokens / honeypot data para detectar discovery.",
        "Alertar en comandos de enumeración del sistema inusuales.",
    ],
    "T1021": [
        "Implementar segmentación de red y microsegmentación.",
        "Restringir SSH/RDP/WinRM a hosts de administración autorizados.",
        "Desplegar monitoreo de tráfico east-west.",
    ],
    "T1005": [
        "Aplicar ACLs de filesystem a directorios de datos.",
        "Habilitar auditoría de acceso a archivos (auditd -w).",
        "Forzar etiquetado de clasificación de datos y políticas DLP.",
    ],
    "T1041": [
        "Implementar filtrado de egress con allowlisting de destinos.",
        "Desplegar DLP con inspección de red para transferencias salientes.",
        "Habilitar monitoreo DNS / sinkholing para dominios anómalos.",
    ],
    "T1486": [
        "Implementar backups offline / inmutables.",
        "Desplegar detecciones EDR de comportamiento de ransomware.",
        "Probar procedimientos de restauración de backup trimestralmente.",
    ],
    "T1499": [
        "Implementar rate limiting y cuotas de conexión.",
        "Monitoreo de disponibilidad con auto-remediación.",
        "Realizar pruebas de carga para validar umbrales de capacidad.",
    ],
}

DEFAULT_RECS = ["Revisar control compensatorio y cobertura de detección para esta técnica."]


class HardeningAgent:
    def recommend(self, technique_id: str, detection_status: str) -> List[str]:
        recs = list(HARDENING_DB.get(technique_id, DEFAULT_RECS))
        if detection_status == "gap":
            recs.append(
                f"CRÍTICO: Crear regla de detección o caso de uso SOC para {technique_id} — "
                "actualmente SIN cobertura."
            )
        elif detection_status == "partial":
            recs.append(
                f"Refinar regla de detección existente para {technique_id} — "
                "cobertura parcial detectada."
            )
        return recs
