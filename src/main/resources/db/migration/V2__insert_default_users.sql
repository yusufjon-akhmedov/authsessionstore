INSERT INTO users (
    full_name,
    email,
    password_hash,
    role,
    enabled,
    created_at,
    updated_at
)
VALUES
    (
        'Default Admin',
        'admin@gmail.com',
        '$2y$10$2ndzh0uf9Zhm9At5jQUnvO59FoUg9enn7gVcT5xriWzlbcQojkXn2',
        'ADMIN',
        true,
        NOW(),
        NOW()
    ),
    (
        'Default User',
        'user@gmail.com',
        '$2y$10$pgjZfLW4ODs5owoQ7n6lH.0DUicuw1K3VZAYuzT6VnPhBiHczSmtu',
        'USER',
        true,
        NOW(),
        NOW()
    )
ON CONFLICT (email) DO NOTHING;