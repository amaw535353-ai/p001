# Executed only in the owned P-010 network-disabled Redmine fixture.
require "securerandom"
abort unless [Redmine::VERSION::MAJOR, Redmine::VERSION::MINOR, Redmine::VERSION::TINY] == [7, 0, 3]

Redmine::DefaultData::Loader.load("en") unless Tracker.exists?
Setting.rest_api_enabled = "1"
Setting.self_registration = "0"
Setting.login_required = "1"
Setting.notified_events = []

marker = "P-010 owned synthetic local remediation project v1"
project = Project.find_by(identifier: "p010-synthetic")
if project
  abort unless project.description == marker && !project.is_public?
else
  project = Project.new(
    name: "P-010 synthetic remediation", identifier: "p010-synthetic",
    description: marker, is_public: false
  )
  project.enabled_module_names = ["issue_tracking"]
  project.trackers = [Tracker.find_by!(name: "Bug")]
  project.save!
end

{"sync" => [:view_issues, :add_issues, :edit_issues], "reader" => [:view_issues]}.each do |label, permissions|
  role = Role.find_or_initialize_by(name: "P010 local #{label}")
  role.permissions = permissions
  role.save!
  user = User.find_or_initialize_by(login: "p010-#{label}")
  if user.new_record?
    user.firstname = "P010"
    user.lastname = label
    user.mail = "p010-#{label}@example.invalid"
    user.password = SecureRandom.hex(32)
    user.mail_notification = "none"
    user.save!
  end
  abort if user.admin?
  member = Member.find_or_initialize_by(project_id: project.id, user_id: user.id)
  member.roles = [role]
  member.save!
  File.open(Rails.root.join(".p010-#{label}-token"), "w", 0600) { |f| f.write(user.api_key) }
end
