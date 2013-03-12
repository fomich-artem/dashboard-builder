/**
 * Copyright (C) 2012 JBoss Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.dashboard.workspace;

import org.jboss.dashboard.workspace.events.ListenerQueue;

/**
* Sections manager, implements operations related to sections management
*/
public interface SectionsManager extends ListenerQueue {

    /**
     * Retrieves a section by identifier.
     */
    Section getSectionByDbId(Long dbid) throws Exception;

    /**
     * Removes a workspace section
     */
    void delete(Section section) throws Exception;

    /**
     * Persist section to database
     */
    void store(Section section) throws Exception;
}