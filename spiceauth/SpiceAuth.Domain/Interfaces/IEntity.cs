namespace SpiceAuth.Domain.Interfaces;

/// <summary>
/// Base interface for all entities in the domain.
/// Provides common properties for identity and auditing.
/// </summary>
public interface IEntity
{
    /// <summary>
    /// Unique identifier for the entity.
    /// </summary>
    Guid Id { get; set; }
    
    /// <summary>
    /// Timestamp when the entity was created.
    /// </summary>
    DateTime CreatedAt { get; set; }
}