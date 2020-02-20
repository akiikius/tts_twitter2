class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  has_many :tweets

  mount_uploader :avatar, AvatarUploader

   #Need to authenticate the user in the db
  validates :username, presence: true, uniqueness: true
  

end
