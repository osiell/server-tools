# -*- encoding: utf-8 -*-
##############################################################################
#
#    Admin Passkey module for Odoo
#    Copyright (C) 2013-2014 GRAP (http://www.grap.coop)
#    @author Sylvain LE GAL (https://twitter.com/legalsylvain)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################################

import datetime

from openerp import api, exceptions, models, SUPERUSER_ID
from openerp.tools.translate import _
from openerp.tools.safe_eval import safe_eval


class ResUsers(models.Model):
    _inherit = "res.users"

    # Private Function section
    @api.model
    def _get_translation(self, lang, text):
        context = {'lang': lang}  # noqa: _() checks page for locals
        return _(text)

    @api.model
    def _send_email_passkey(self, user_agent_env):
        """ Send a email to the admin of the system and / or the user
 to inform passkey use."""
        mails = []
        mail_obj = self.env['mail.mail'].sudo()
        icp_obj = self.env['ir.config_parameter'].sudo()
        admin_user = self.browse(SUPERUSER_ID)
        login_user = self.env.user
        send_to_admin = safe_eval(icp_obj.get_param(
            'auth_admin_passkey.send_to_admin', 'True'))
        send_to_user = safe_eval(icp_obj.get_param(
            'auth_admin_passkey.send_to_user', 'True'))

        if send_to_admin and admin_user.email:
            mails.append({'email': admin_user.email, 'lang': admin_user.lang})
        if send_to_user and login_user.email:
            mails.append({'email': login_user.email, 'lang': login_user.lang})

        for mail in mails:
            subject = self._get_translation(
                mail['lang'], _('Passkey used'))
            body = self._get_translation(
                mail['lang'],
                _("""Admin user used his passkey to login with '%s'.\n\n"""
                    """\n\nTechnicals informations belows : \n\n"""
                    """- Login date : %s\n\n""")) % (
                        login_user.login,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            for k, v in user_agent_env.iteritems():
                body += ("- %s : %s\n\n") % (k, v)
            mail_obj.create({
                'email_to': mail['email'],
                'subject': subject,
                'body_html': '<pre>%s</pre>' % body
            })

    @api.model
    def _send_email_same_password(self, login_user):
        """ Send a email to the admin user to inform that another user has the
 same password as him."""
        mail_obj = self.env['mail.mail'].sudo()
        admin_user = self.browse(SUPERUSER_ID)
        if admin_user.email:
            mail_obj.create({
                'email_to': admin_user.email,
                'subject': self._get_translation(
                    admin_user.lang, _('[WARNING] Odoo Security Risk')),
                'body_html': self._get_translation(
                    admin_user.lang, _(
                        """<pre>User with login '%s' has the same """
                        """password as you.</pre>""")) % (login_user),
            })

    # Overload Section
    @classmethod
    def authenticate(cls, db, login, password, user_agent_env):
        """ Authenticate the user 'login' is password is ok or if
 is admin password. In the second case, send mail to user and admin."""
        user_id = super(ResUsers, cls).authenticate(
            db, login, password, user_agent_env)
        if user_id and (user_id != SUPERUSER_ID):
            same_password = False
            with cls.pool.cursor() as cr:
                env = api.Environment(cr, SUPERUSER_ID, {})
                user = env[cls._name].browse(user_id)
                try:
                    # directly use parent 'check_credentials' function
                    # to really know if credentials are ok
                    # or if it was admin password
                    super(ResUsers, env.user).check_credentials(password)
                    try:
                        # Test now if the user has the same
                        # password as admin user
                        super(ResUsers, user).check_credentials(password)
                        same_password = True
                    except exceptions.AccessDenied:
                        pass
                    if not same_password:
                        user._send_email_passkey(user_agent_env)
                    else:
                        user._send_email_same_password(login)
                    env.cr.commit()
                except exceptions.AccessDenied:
                    pass
        return user_id

    @api.model
    def check_credentials(self, password):
        """ Return now True if credentials are good OR if password is admin
password."""
        if self._uid != SUPERUSER_ID:
            try:
                super(ResUsers, self).check_credentials(password)
                return True
            except exceptions.AccessDenied:
                return self.sudo().check_credentials(password)
        else:
            return super(ResUsers, self).check_credentials(password)
