using System;
using System.Security.Cryptography;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Microsoft.AspNetCore.Identity;
using SafeVault.Models;

namespace SafeVault.Services
{
    // Argon2id-based IPasswordHasher<User> using Isopoh.Cryptography.Argon2.
    // This implementation provides secure hashing with sensible defaults; tune
    // parameters for your production environment based on benchmarking.
    public class Argon2PasswordHasher : IPasswordHasher<User>
    {
        // Production-oriented defaults: increase memory and iterations to raise attacker cost.
        // These values are a sensible starting point for modern servers; tune them on
        // representative production hardware to balance security and latency.
        // - MemorySizeKB: 256 MB (262144 KB)
        // - Iterations (time cost): 4
        // - DegreeOfParallelism: number of logical processors (bounded to at least 1)
        private const int SaltSize = 16; // bytes
        private const int HashSize = 32; // bytes
        private const int MemorySizeKB = 262_144; // 256 MB
        private const int Iterations = 4;
        private static readonly int DegreeOfParallelism = Math.Max(1, Environment.ProcessorCount);

        public string HashPassword(User user, string password)
        {
            ArgumentNullException.ThrowIfNull(user);
            ArgumentNullException.ThrowIfNull(password);

            // Generate a cryptographically secure random salt
            var salt = new byte[SaltSize];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            // Produce an encoded Argon2 string in the modular crypt-like format.
            var encoded = HashWithArgon2id(password, salt);
            return encoded;
        }

        public PasswordVerificationResult VerifyHashedPassword(User user, string hashedPassword, string providedPassword)
        {
            ArgumentNullException.ThrowIfNull(hashedPassword);
            if (providedPassword is null) return PasswordVerificationResult.Failed;

            try
            {
                var ok = Argon2.Verify(hashedPassword, providedPassword);
                return ok ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
            }
            catch
            {
                // Treat any parse or verification error as a failed password verification.
                return PasswordVerificationResult.Failed;
            }
        }

        private static string HashWithArgon2id(string password, byte[] salt)
        {
            var config = new Argon2Config
            {
                Version = Argon2Version.Nineteen,
                TimeCost = Iterations,
                MemoryCost = MemorySizeKB,
                Lanes = DegreeOfParallelism,
                Salt = salt,
                Password = Encoding.UTF8.GetBytes(password),
                HashLength = HashSize
            };

            // Returns an encoded Argon2id string (for example: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>)
            return Argon2.Hash(config);
        }

    }
}
