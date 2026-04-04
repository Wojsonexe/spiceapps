using SpiceAuth.Core.Enums;

namespace SpiceAuth.Core.Entities.Security;

public class AuditLog : BaseEntity
{
    // ─── Kto wykonał akcję ────────────────────────────────────────────────────
    public Guid? UserId { get; set; }
    public string ActorEmail { get; set; } = null!;

    // ─── Kontekst ─────────────────────────────────────────────────────────────
    public Guid? ClientId { get; set; }
    public Guid? OrganizationId { get; set; }

    // ─── Akcja ────────────────────────────────────────────────────────────────
    public AuditAction Action { get; set; }

    // ─── Cel akcji ────────────────────────────────────────────────────────────
    public string? ResourceType { get; set; }        // "User" | "Client" | "Registration"
    public string? ResourceId { get; set; }          // UUID lub string ID
    public string? ResourceName { get; set; }

    // ─── Request info ─────────────────────────────────────────────────────────
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }

    // ─── Wynik ────────────────────────────────────────────────────────────────
    public bool Success { get; set; }
    public string? FailureReason { get; set; }

    // ─── Dodatkowe dane (JSON) ────────────────────────────────────────────────
    public string? Metadata { get; set; }            // np. rejection reason, changed fields

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}