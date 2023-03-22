class User < ApplicationRecord
    has_secure_pasword
    validates :username, uniqueness: { case_sensitive: false }
end
