/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.beach.security;

import org.junit.Test;

import java.net.URL;
import java.security.*;

/**
 * @author <a href="mailto:cdewolf@redhat.com">Carlo de Wolf</a>
 */
public class FakeProtectionDomainTestCase {
    private static CodeSource codeSource(Class<?> cls) {
        return cls.getProtectionDomain().getCodeSource();
    }

    private static PermissionCollection permissions(final Permission... permissions) {
        final PermissionCollection result = new Permissions();
        for (Permission p : permissions) {
            result.add(p);
        }
        result.setReadOnly();
        return result;
    }

    @Test
    public void testFakeContext() throws Exception {
        final CodeSource codeSource = new CodeSource(new URL("file:/dummy"), (CodeSigner[]) null);
        final PermissionCollection permissions = new Permissions();
        permissions.add(new RuntimePermission("getenv.USER"));
        final ProtectionDomain[] domains = { new ProtectionDomain(codeSource, permissions), new ProtectionDomain(codeSource(FakeProtectionDomainTestCase.class), permissions(new AllPermission())) };
        final AccessControlContext context = new AccessControlContext(domains);
        final AccessControlContext context2 = new AccessControlContext(context, new DomainCombiner() {
            @Override
            public ProtectionDomain[] combine(ProtectionDomain[] currentDomains, ProtectionDomain[] assignedDomains) {
                return assignedDomains;
            }
        });
        try {
            System.setSecurityManager(new SecurityManager() {
                @Override
                public void checkPermission(Permission perm) {
                    // so we can set back
                    if (perm instanceof RuntimePermission && perm.getName().equals("setSecurityManager")) {
                        return;
                    }
                    super.checkPermission(perm);
                }
            });
            AccessController.doPrivileged(new PrivilegedAction<String>() {
                @Override
                public String run() {
                    return System.getenv("USER");
                }
            }, context2);
        }
        finally {
            System.setSecurityManager(null);
        }
    }
}
